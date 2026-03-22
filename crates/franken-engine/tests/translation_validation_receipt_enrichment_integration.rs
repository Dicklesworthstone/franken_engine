//! Enrichment integration tests for translation_validation_receipt module.
//!
//! Covers gaps not addressed by the base integration test suite:
//! - Schema constant prefix, uniqueness, and format validation
//! - Serde roundtrips for EmitterConfig, EmitterStats, ChainIntegrityResult,
//!   ChainIntegrityIssue, ReceiptSummary, EmitResult, ReceiptChainError
//! - Hash sensitivity for FailureReceipt and receipt fields
//! - ProofEvidence hash sensitivity on steps/ticks/metadata
//! - Chain hash mutation on append/record_failure
//! - Display output precision for ReceiptChainError, FailureKind, ReceiptVerdict
//! - Boundary conditions: significance threshold, empty IDs, positive deltas
//! - Quarantine of multiple optimizations
//! - Failure pruning in chain
//! - Default cost model ID fallback
//! - EmitResult variant access patterns
//! - Emitter with custom signing key
//! - Empty rules on disproven/inconclusive paths
//! - Chain integrity with issues
//! - Full emitter serde roundtrip with rich state

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
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::translation_validation_receipt::*;
use frankenengine_engine::versioned_rewrite_pack::{PackVersion, RewriteCategory};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

fn rule(id: &str, cost_delta: i64) -> AppliedRuleRecord {
    AppliedRuleRecord {
        pack_id: "enrichment-pack".into(),
        pack_version: PackVersion::CURRENT,
        rule_id: id.into(),
        category: RewriteCategory::AlgebraicSimplification,
        before_hash: hash(b"before"),
        after_hash: hash(b"after"),
        cost_delta_millionths: cost_delta,
        rule_proven_sound: true,
    }
}

fn dce_rule(id: &str, cost_delta: i64) -> AppliedRuleRecord {
    AppliedRuleRecord {
        pack_id: "enrichment-pack".into(),
        pack_version: PackVersion::CURRENT,
        rule_id: id.into(),
        category: RewriteCategory::DeadCodeElimination,
        before_hash: hash(id.as_bytes()),
        after_hash: hash(format!("{id}-after").as_bytes()),
        cost_delta_millionths: cost_delta,
        rule_proven_sound: true,
    }
}

fn proven() -> ReceiptVerdict {
    ReceiptVerdict::Proven {
        evidence: ProofEvidence::new(ProofMode::Symbolic, hash(b"proof"), 50, 2000),
    }
}

fn disproven() -> ReceiptVerdict {
    ReceiptVerdict::Disproven {
        counterexample_hash: hash(b"counter"),
        divergence: "output differs on test case #3".into(),
    }
}

fn inconclusive() -> ReceiptVerdict {
    ReceiptVerdict::Inconclusive {
        reason: "solver timeout after 10M steps".into(),
        budget_consumed_ticks: 10_000_000,
        budget_limit_ticks: 10_000_000,
    }
}

fn emitter() -> ValidationReceiptEmitter {
    ValidationReceiptEmitter::new(EmitterConfig::default(), epoch(1))
}

fn input(opt_id: &str, verdict: ReceiptVerdict) -> EmitInput {
    EmitInput {
        optimization_id: opt_id.into(),
        baseline_ir_hash: hash(b"baseline-ir"),
        optimized_ir_hash: hash(b"optimized-ir"),
        applied_rules: vec![rule("r-alg-1", -200_000)],
        verdict,
        cost_model_id: None,
    }
}

fn make_receipt(
    seq: u64,
    opt_id: &str,
    parent: Option<ContentHash>,
    ep: SecurityEpoch,
    ticks: u64,
    rules: Vec<AppliedRuleRecord>,
    verdict: ReceiptVerdict,
) -> TranslationValidationReceipt {
    TranslationValidationReceipt::new(
        seq,
        opt_id,
        parent,
        ep,
        ticks,
        hash(b"b"),
        hash(b"o"),
        rules,
        verdict,
        "cm",
    )
}

// ===========================================================================
// 1. Schema constant validation
// ===========================================================================

#[test]
fn enrichment_schema_constants_have_franken_engine_prefix() {
    assert!(
        RECEIPT_SCHEMA_VERSION.starts_with("franken-engine."),
        "RECEIPT_SCHEMA_VERSION must start with 'franken-engine.'"
    );
    assert!(
        CHAIN_SCHEMA_VERSION.starts_with("franken-engine."),
        "CHAIN_SCHEMA_VERSION must start with 'franken-engine.'"
    );
    assert!(
        SUMMARY_SCHEMA_VERSION.starts_with("franken-engine."),
        "SUMMARY_SCHEMA_VERSION must start with 'franken-engine.'"
    );
}

#[test]
fn enrichment_schema_constants_are_unique() {
    let mut versions = BTreeSet::new();
    versions.insert(RECEIPT_SCHEMA_VERSION);
    versions.insert(CHAIN_SCHEMA_VERSION);
    versions.insert(SUMMARY_SCHEMA_VERSION);
    assert_eq!(
        versions.len(),
        3,
        "All three schema version constants must be distinct"
    );
}

#[test]
fn enrichment_component_constant_is_module_name() {
    assert_eq!(COMPONENT, "translation_validation_receipt");
    assert!(COMPONENT.chars().all(|c| c.is_alphanumeric() || c == '_'));
}

#[test]
fn enrichment_bead_id_has_expected_prefix() {
    assert!(BEAD_ID.starts_with("bd-"), "BEAD_ID must start with 'bd-'");
}

#[test]
fn enrichment_max_constants_are_positive() {
    assert!(MAX_CHAIN_LENGTH > 0);
    assert!(MAX_RULES_PER_RECEIPT > 0);
    assert!(SIGNIFICANT_IMPROVEMENT_THRESHOLD > 0);
}

// ===========================================================================
// 2. Serde roundtrips for types not covered in base suite
// ===========================================================================

#[test]
fn enrichment_serde_emitter_config_roundtrip() {
    let cfg = EmitterConfig {
        chain_id: "custom-chain".into(),
        signing_key: vec![42u8; 32],
        max_chain_length: 128,
        quarantine_on_first_failure: false,
        proof_budget_ticks: 5_000_000,
        default_cost_model_id: "custom-cost-v3".into(),
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: EmitterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

#[test]
fn enrichment_serde_emitter_stats_roundtrip() {
    let stats = EmitterStats {
        total_receipts: 42,
        total_proven: 30,
        total_disproven: 7,
        total_inconclusive: 5,
        total_rules_applied: 100,
        total_cost_improvement_millionths: -2_500_000,
        total_quarantined: 3,
        total_verifications: 20,
        verification_failures: 1,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let restored: EmitterStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, restored);
}

#[test]
fn enrichment_serde_emitter_stats_default_roundtrip() {
    let stats = EmitterStats::default();
    let json = serde_json::to_string(&stats).unwrap();
    let restored: EmitterStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, restored);
    assert_eq!(restored.total_receipts, 0);
}

#[test]
fn enrichment_serde_chain_integrity_result_roundtrip() {
    let result = ChainIntegrityResult {
        valid: true,
        receipt_count: 10,
        issues: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ChainIntegrityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_serde_chain_integrity_result_with_issues_roundtrip() {
    let result = ChainIntegrityResult {
        valid: false,
        receipt_count: 5,
        issues: vec![
            ChainIntegrityIssue::ParentHashBroken {
                sequence: 3,
                expected_parent: Some(hash(b"expected")),
                actual_parent: Some(hash(b"actual")),
            },
            ChainIntegrityIssue::SequenceNonMonotonic {
                position: 2,
                sequence: 1,
                previous_sequence: 5,
            },
        ],
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ChainIntegrityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_serde_chain_integrity_issue_parent_hash_broken() {
    let issue = ChainIntegrityIssue::ParentHashBroken {
        sequence: 7,
        expected_parent: None,
        actual_parent: Some(hash(b"orphan")),
    };
    let json = serde_json::to_string(&issue).unwrap();
    let restored: ChainIntegrityIssue = serde_json::from_str(&json).unwrap();
    assert_eq!(issue, restored);
}

#[test]
fn enrichment_serde_chain_integrity_issue_sequence_non_monotonic() {
    let issue = ChainIntegrityIssue::SequenceNonMonotonic {
        position: 4,
        sequence: 2,
        previous_sequence: 3,
    };
    let json = serde_json::to_string(&issue).unwrap();
    let restored: ChainIntegrityIssue = serde_json::from_str(&json).unwrap();
    assert_eq!(issue, restored);
}

#[test]
fn enrichment_serde_receipt_chain_error_parent_hash_mismatch() {
    let err = ReceiptChainError::ParentHashMismatch {
        expected: Some(hash(b"parent")),
        actual: None,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ReceiptChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_serde_receipt_chain_error_sequence_gap() {
    let err = ReceiptChainError::SequenceGap {
        expected: 10,
        actual: 15,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: ReceiptChainError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_serde_emit_result_approved_roundtrip() {
    let mut em = emitter();
    let result = em.emit(input("opt-serde-approved", proven()));
    let json = serde_json::to_string(&result).unwrap();
    let restored: EmitResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    assert!(restored.is_approved());
}

#[test]
fn enrichment_serde_emit_result_rejected_roundtrip() {
    let mut em = emitter();
    let result = em.emit(input("opt-serde-rejected", disproven()));
    let json = serde_json::to_string(&result).unwrap();
    let restored: EmitResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
    assert!(!restored.is_approved());
}

#[test]
fn enrichment_serde_emit_result_quarantined_roundtrip() {
    let mut em = emitter();
    em.quarantine_optimization("opt-q");
    let result = em.emit(input("opt-q", proven()));
    let json = serde_json::to_string(&result).unwrap();
    let restored: EmitResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_serde_receipt_summary_roundtrip() {
    let mut em = emitter();
    em.emit(input("opt-1", proven()));
    em.emit(input("opt-2", disproven()));
    em.emit(input("opt-3", inconclusive()));
    let summary = em.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let restored: ReceiptSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// ===========================================================================
// 3. Display format verification
// ===========================================================================

#[test]
fn enrichment_receipt_chain_error_parent_hash_mismatch_display() {
    let err = ReceiptChainError::ParentHashMismatch {
        expected: None,
        actual: Some(hash(b"x")),
    };
    let s = err.to_string();
    assert!(
        s.contains("parent hash mismatch"),
        "ParentHashMismatch Display must contain 'parent hash mismatch', got: {s}"
    );
}

#[test]
fn enrichment_receipt_chain_error_sequence_gap_display_content() {
    let err = ReceiptChainError::SequenceGap {
        expected: 7,
        actual: 12,
    };
    let s = err.to_string();
    assert!(s.contains("sequence gap"), "must mention 'sequence gap'");
    assert!(s.contains("7"), "must contain expected sequence");
    assert!(s.contains("12"), "must contain actual sequence");
}

#[test]
fn enrichment_failure_kind_budget_exceeded_display_content() {
    let k = FailureKind::BudgetExceeded {
        consumed_ticks: 9999,
        limit_ticks: 10000,
    };
    let s = k.to_string();
    assert!(
        s.contains("budget"),
        "BudgetExceeded display must mention 'budget'"
    );
    assert!(s.contains("9999"), "must show consumed ticks");
    assert!(s.contains("10000"), "must show limit ticks");
}

#[test]
fn enrichment_failure_kind_interference_display_count() {
    let k = FailureKind::InterferenceDetected {
        conflicting_rules: vec!["a".into(), "b".into(), "c".into()],
    };
    let s = k.to_string();
    assert!(s.contains("interference"), "must mention 'interference'");
    assert!(s.contains("3"), "must show count of conflicting rules");
}

#[test]
fn enrichment_failure_kind_complexity_exceeded_display_content() {
    let k = FailureKind::ComplexityExceeded {
        metric: "ir_nodes".into(),
        value: 100_000,
        limit: 50_000,
    };
    let s = k.to_string();
    assert!(s.contains("complexity"), "must mention 'complexity'");
    assert!(s.contains("ir_nodes"), "must show metric name");
    assert!(s.contains("100000"), "must show value");
    assert!(s.contains("50000"), "must show limit");
}

#[test]
fn enrichment_failure_kind_malformed_output_display_detail() {
    let k = FailureKind::MalformedOutput {
        detail: "dangling phi node at block 7".into(),
    };
    let s = k.to_string();
    assert!(s.contains("malformed"), "must mention 'malformed'");
    assert!(s.contains("dangling phi node"), "must include detail text");
}

#[test]
fn enrichment_verdict_proven_display_includes_mode() {
    let v = ReceiptVerdict::Proven {
        evidence: ProofEvidence::new(ProofMode::GoldenCorpus, hash(b"gc"), 10, 100),
    };
    let s = v.to_string();
    assert!(s.starts_with("PROVEN"));
    assert!(s.contains("golden_corpus"), "must include the proof mode");
}

#[test]
fn enrichment_verdict_disproven_display_includes_divergence() {
    let v = ReceiptVerdict::Disproven {
        counterexample_hash: hash(b"cx"),
        divergence: "register r7 differs".into(),
    };
    let s = v.to_string();
    assert!(s.starts_with("DISPROVEN"));
    assert!(
        s.contains("register r7 differs"),
        "must include divergence text"
    );
}

#[test]
fn enrichment_verdict_inconclusive_display_includes_reason() {
    let v = ReceiptVerdict::Inconclusive {
        reason: "memory limit reached".into(),
        budget_consumed_ticks: 1,
        budget_limit_ticks: 2,
    };
    let s = v.to_string();
    assert!(s.starts_with("INCONCLUSIVE"));
    assert!(
        s.contains("memory limit reached"),
        "must include the reason"
    );
}

// ===========================================================================
// 4. Hash sensitivity tests
// ===========================================================================

#[test]
fn enrichment_receipt_hash_sensitive_to_optimization_id() {
    let r1 = make_receipt(1, "opt-A", None, epoch(1), 0, vec![], proven());
    let r2 = make_receipt(1, "opt-B", None, epoch(1), 0, vec![], proven());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_epoch() {
    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    let r2 = make_receipt(1, "opt", None, epoch(2), 0, vec![], proven());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_timestamp_ticks() {
    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    let r2 = make_receipt(1, "opt", None, epoch(1), 1, vec![], proven());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_parent_hash() {
    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    let r2 = make_receipt(
        1,
        "opt",
        Some(hash(b"parent")),
        epoch(1),
        0,
        vec![],
        proven(),
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_verdict_variant() {
    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    let r2 = make_receipt(1, "opt", None, epoch(1), 0, vec![], disproven());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_rule_cost_delta() {
    let r1 = make_receipt(
        1,
        "opt",
        None,
        epoch(1),
        0,
        vec![rule("r1", -100)],
        proven(),
    );
    let r2 = make_receipt(
        1,
        "opt",
        None,
        epoch(1),
        0,
        vec![rule("r1", -200)],
        proven(),
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_rule_order() {
    let r1 = make_receipt(
        1,
        "opt",
        None,
        epoch(1),
        0,
        vec![rule("r-a", -100), rule("r-b", -200)],
        proven(),
    );
    let r2 = make_receipt(
        1,
        "opt",
        None,
        epoch(1),
        0,
        vec![rule("r-b", -200), rule("r-a", -100)],
        proven(),
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_baseline_ir_hash() {
    let r1 = TranslationValidationReceipt::new(
        1,
        "opt",
        None,
        epoch(1),
        0,
        hash(b"baseline-A"),
        hash(b"optimized"),
        vec![],
        proven(),
        "cm",
    );
    let r2 = TranslationValidationReceipt::new(
        1,
        "opt",
        None,
        epoch(1),
        0,
        hash(b"baseline-B"),
        hash(b"optimized"),
        vec![],
        proven(),
        "cm",
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_optimized_ir_hash() {
    let r1 = TranslationValidationReceipt::new(
        1,
        "opt",
        None,
        epoch(1),
        0,
        hash(b"baseline"),
        hash(b"optimized-A"),
        vec![],
        proven(),
        "cm",
    );
    let r2 = TranslationValidationReceipt::new(
        1,
        "opt",
        None,
        epoch(1),
        0,
        hash(b"baseline"),
        hash(b"optimized-B"),
        vec![],
        proven(),
        "cm",
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_cost_model_id() {
    let r1 = TranslationValidationReceipt::new(
        1,
        "opt",
        None,
        epoch(1),
        0,
        hash(b"baseline"),
        hash(b"optimized"),
        vec![],
        proven(),
        "cm-a",
    );
    let r2 = TranslationValidationReceipt::new(
        1,
        "opt",
        None,
        epoch(1),
        0,
        hash(b"baseline"),
        hash(b"optimized"),
        vec![],
        proven(),
        "cm-b",
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_rule_pack_metadata() {
    let left_rule = rule("r1", -100);
    let mut right_rule = left_rule.clone();
    right_rule.pack_id = "different-pack".into();

    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![left_rule], proven());
    let r2 = make_receipt(1, "opt", None, epoch(1), 0, vec![right_rule], proven());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_rule_pack_version() {
    let left_rule = rule("r1", -100);
    let mut right_rule = left_rule.clone();
    right_rule.pack_version = PackVersion { major: 1, minor: 1 };

    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![left_rule], proven());
    let r2 = make_receipt(1, "opt", None, epoch(1), 0, vec![right_rule], proven());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_rule_category_and_soundness() {
    let left_rule = rule("r1", -100);
    let mut right_rule = left_rule.clone();
    right_rule.category = RewriteCategory::DeadCodeElimination;
    right_rule.rule_proven_sound = false;

    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![left_rule], proven());
    let r2 = make_receipt(1, "opt", None, epoch(1), 0, vec![right_rule], proven());
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_proven_evidence_contents() {
    let verdict_a = ReceiptVerdict::Proven {
        evidence: ProofEvidence::new(ProofMode::Symbolic, hash(b"proof-a"), 50, 2000)
            .with_metadata("solver", "z3"),
    };
    let verdict_b = ReceiptVerdict::Proven {
        evidence: ProofEvidence::new(ProofMode::Symbolic, hash(b"proof-b"), 50, 2000)
            .with_metadata("solver", "cvc5"),
    };

    let r1 = make_receipt(1, "opt", None, epoch(1), 0, vec![], verdict_a);
    let r2 = make_receipt(1, "opt", None, epoch(1), 0, vec![], verdict_b);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_sensitive_to_disproven_and_inconclusive_details() {
    let disproven_a = ReceiptVerdict::Disproven {
        counterexample_hash: hash(b"counter-a"),
        divergence: "mismatch-a".into(),
    };
    let disproven_b = ReceiptVerdict::Disproven {
        counterexample_hash: hash(b"counter-b"),
        divergence: "mismatch-b".into(),
    };
    let inconclusive_a = ReceiptVerdict::Inconclusive {
        reason: "solver timeout".into(),
        budget_consumed_ticks: 10,
        budget_limit_ticks: 20,
    };
    let inconclusive_b = ReceiptVerdict::Inconclusive {
        reason: "memory limit".into(),
        budget_consumed_ticks: 11,
        budget_limit_ticks: 21,
    };

    let disproven_left = make_receipt(1, "opt", None, epoch(1), 0, vec![], disproven_a);
    let disproven_right = make_receipt(1, "opt", None, epoch(1), 0, vec![], disproven_b);
    let inconclusive_left = make_receipt(1, "opt", None, epoch(1), 0, vec![], inconclusive_a);
    let inconclusive_right = make_receipt(1, "opt", None, epoch(1), 0, vec![], inconclusive_b);

    assert_ne!(disproven_left.content_hash, disproven_right.content_hash);
    assert_ne!(
        inconclusive_left.content_hash,
        inconclusive_right.content_hash
    );
}

#[test]
fn enrichment_proof_evidence_hash_sensitive_to_metadata() {
    let ev1 =
        ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 100).with_metadata("key", "val1");
    let ev2 =
        ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 100).with_metadata("key", "val2");
    assert_ne!(ev1.content_hash(), ev2.content_hash());
}

#[test]
fn enrichment_proof_evidence_hash_sensitive_to_verification_steps() {
    let ev1 = ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 100);
    let ev2 = ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 20, 100);
    assert_ne!(ev1.content_hash(), ev2.content_hash());
}

#[test]
fn enrichment_proof_evidence_hash_sensitive_to_verification_ticks() {
    let ev1 = ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 100);
    let ev2 = ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 200);
    assert_ne!(ev1.content_hash(), ev2.content_hash());
}

#[test]
fn enrichment_failure_receipt_hash_deterministic() {
    let f1 = FailureReceipt::new(
        "opt-f",
        "pack-1",
        PackVersion::CURRENT,
        vec!["r1".into()],
        FailureKind::CounterexampleFound {
            divergence: "x".into(),
        },
        Some(hash(b"cx")),
        true,
        epoch(3),
        999,
    );
    let f2 = FailureReceipt::new(
        "opt-f",
        "pack-1",
        PackVersion::CURRENT,
        vec!["r1".into()],
        FailureKind::CounterexampleFound {
            divergence: "x".into(),
        },
        Some(hash(b"cx")),
        true,
        epoch(3),
        999,
    );
    assert_eq!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrichment_failure_receipt_hash_sensitive_to_opt_id() {
    let f1 = FailureReceipt::new(
        "opt-A",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    let f2 = FailureReceipt::new(
        "opt-B",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrichment_failure_receipt_hash_sensitive_to_pack_id() {
    let f1 = FailureReceipt::new(
        "opt",
        "pack-A",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    let f2 = FailureReceipt::new(
        "opt",
        "pack-B",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrichment_failure_receipt_hash_sensitive_to_failure_kind() {
    let f1 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::CounterexampleFound {
            divergence: "x".into(),
        },
        None,
        false,
        epoch(1),
        0,
    );
    let f2 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput {
            detail: "bad ir".into(),
        },
        None,
        false,
        epoch(1),
        0,
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrichment_failure_receipt_hash_sensitive_to_timestamp() {
    let f1 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        100,
    );
    let f2 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        200,
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrichment_failure_receipt_hash_sensitive_to_epoch() {
    let f1 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    let f2 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(2),
        0,
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrichment_failure_receipt_hash_sensitive_to_pack_version_and_quarantine_flag() {
    let f1 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec!["r1".into()],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    let f2 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion { major: 1, minor: 1 },
        vec!["r1".into()],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        true,
        epoch(1),
        0,
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrichment_failure_receipt_hash_sensitive_to_interference_rule_contents() {
    let f1 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec!["r1".into()],
        FailureKind::InterferenceDetected {
            conflicting_rules: vec!["a".into(), "b".into()],
        },
        None,
        false,
        epoch(1),
        0,
    );
    let f2 = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec!["r1".into()],
        FailureKind::InterferenceDetected {
            conflicting_rules: vec!["a".into(), "c".into()],
        },
        None,
        false,
        epoch(1),
        0,
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

// ===========================================================================
// 5. Edge cases in core logic
// ===========================================================================

#[test]
fn enrichment_applied_rule_at_exact_significance_threshold() {
    let at_threshold = rule("r-thresh", -SIGNIFICANT_IMPROVEMENT_THRESHOLD);
    assert!(at_threshold.is_improvement());
    assert!(!at_threshold.is_significant_improvement());
}

#[test]
fn enrichment_applied_rule_one_below_significance_threshold() {
    let below = rule("r-below", -SIGNIFICANT_IMPROVEMENT_THRESHOLD - 1);
    assert!(below.is_improvement());
    assert!(below.is_significant_improvement());
}

#[test]
fn enrichment_applied_rule_positive_cost_delta_not_improvement() {
    let worse = rule("r-worse", 500_000);
    assert!(!worse.is_improvement());
    assert!(!worse.is_significant_improvement());
}

#[test]
fn enrichment_receipt_is_failure_for_all_non_proven() {
    let proven_r = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    assert!(!proven_r.is_failure());
    assert!(proven_r.permits_activation());

    let disproven_r = make_receipt(1, "opt", None, epoch(1), 0, vec![], disproven());
    assert!(disproven_r.is_failure());
    assert!(!disproven_r.permits_activation());

    let inconclusive_r = make_receipt(1, "opt", None, epoch(1), 0, vec![], inconclusive());
    assert!(inconclusive_r.is_failure());
    assert!(!inconclusive_r.permits_activation());
}

#[test]
fn enrichment_verdict_permits_activation_only_for_proven() {
    assert!(proven().permits_activation());
    assert!(!disproven().permits_activation());
    assert!(!inconclusive().permits_activation());
}

#[test]
fn enrichment_verdict_is_disproven_only_for_disproven() {
    assert!(!proven().is_disproven());
    assert!(disproven().is_disproven());
    assert!(!inconclusive().is_disproven());
}

#[test]
fn enrichment_receipt_zero_rules_not_net_improvement() {
    let r = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    assert!(!r.is_net_improvement());
    assert_eq!(r.total_cost_delta_millionths, 0);
    assert_eq!(r.rule_count(), 0);
}

#[test]
fn enrichment_receipt_positive_cost_delta_not_net_improvement() {
    let r = make_receipt(
        1,
        "opt",
        None,
        epoch(1),
        0,
        vec![rule("r-worse", 100_000)],
        proven(),
    );
    assert!(!r.is_net_improvement());
    assert_eq!(r.total_cost_delta_millionths, 100_000);
}

#[test]
fn enrichment_receipt_all_rules_proven_sound_with_empty_rules() {
    let r = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    assert!(r.all_rules_proven_sound());
    assert_eq!(r.proven_sound_rule_count(), 0);
}

#[test]
fn enrichment_receipt_schema_version_set_on_construction() {
    let r = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    assert_eq!(r.schema_version, RECEIPT_SCHEMA_VERSION);
}

#[test]
fn enrichment_receipt_rewrite_categories_collected() {
    let rules = vec![rule("r1", -100), dce_rule("r2", -200), rule("r3", -50)];
    let r = make_receipt(1, "opt", None, epoch(1), 0, rules, proven());
    assert_eq!(r.rewrite_categories.len(), 2);
    assert!(
        r.rewrite_categories
            .contains(&RewriteCategory::AlgebraicSimplification)
    );
    assert!(
        r.rewrite_categories
            .contains(&RewriteCategory::DeadCodeElimination)
    );
}

#[test]
fn enrichment_receipt_cost_delta_sums_across_rules() {
    let rules = vec![
        rule("r1", -100_000),
        rule("r2", -200_000),
        rule("r3", 50_000),
    ];
    let r = make_receipt(1, "opt", None, epoch(1), 0, rules, proven());
    assert_eq!(r.total_cost_delta_millionths, -250_000);
    assert!(r.is_net_improvement());
}

#[test]
fn enrichment_receipt_collects_deduplicated_rewrite_categories() {
    let mut r1 = rule("r1", -100);
    r1.category = RewriteCategory::CommonSubexpression;
    let mut r2 = rule("r2", -200);
    r2.category = RewriteCategory::PartialEvaluation;
    let mut r3 = rule("r3", -300);
    r3.category = RewriteCategory::CommonSubexpression; // duplicate

    let receipt = make_receipt(1, "opt", None, epoch(1), 0, vec![r1, r2, r3], proven());
    assert_eq!(receipt.rewrite_categories.len(), 2);
    assert!(
        receipt
            .rewrite_categories
            .contains(&RewriteCategory::CommonSubexpression)
    );
    assert!(
        receipt
            .rewrite_categories
            .contains(&RewriteCategory::PartialEvaluation)
    );
}

#[test]
fn enrichment_very_large_cost_deltas() {
    let r = rule("r-huge", -999_999_999);
    assert!(r.is_improvement());
    assert!(r.is_significant_improvement());

    let receipt = make_receipt(1, "opt", None, epoch(1), 0, vec![r], proven());
    assert_eq!(receipt.total_cost_delta_millionths, -999_999_999);
    assert!(receipt.is_net_improvement());
}

// ===========================================================================
// 6. Signing and verification edge cases
// ===========================================================================

#[test]
fn enrichment_sign_with_custom_key_and_verify() {
    let key = b"my-custom-key-for-signing-tests!";
    let r = make_receipt(
        1,
        "opt",
        None,
        epoch(1),
        0,
        vec![rule("r1", -100)],
        proven(),
    )
    .sign(key);
    assert!(r.verify_signature(key));
    assert!(!r.verify_signature(b"wrong-key-wrong-key-wrong-key!!x"));
}

#[test]
fn enrichment_unsigned_receipt_fails_custom_key_verification() {
    let r = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    assert!(!r.verify_signature(b"any-non-trivial-key-must-fail!!!"));
}

#[test]
fn enrichment_emitter_custom_signing_key_used() {
    let config = EmitterConfig {
        signing_key: vec![99u8; 32],
        ..Default::default()
    };
    let mut em = ValidationReceiptEmitter::new(config.clone(), epoch(1));
    let result = em.emit(input("opt-ck", proven()));
    let receipt = result.receipt().unwrap();
    assert!(receipt.verify_signature(&config.signing_key));
    assert!(!receipt.verify_signature(&[0u8; 32]));
}

// ===========================================================================
// 7. Chain operations edge cases
// ===========================================================================

#[test]
fn enrichment_chain_with_max_length_builder() {
    let chain = ReceiptChain::new("c", epoch(1)).with_max_length(10);
    assert_eq!(chain.max_length, 10);
}

#[test]
fn enrichment_empty_chain_verify_integrity() {
    let chain = ReceiptChain::new("c", epoch(1));
    let result = chain.verify_integrity();
    assert!(result.valid);
    assert_eq!(result.receipt_count, 0);
    assert!(result.issues.is_empty());
}

#[test]
fn enrichment_empty_chain_queries() {
    let chain = ReceiptChain::new("c", epoch(1));
    assert!(chain.last_receipt().is_none());
    assert_eq!(chain.success_count(), 0);
    assert_eq!(chain.rejected_count(), 0);
    assert_eq!(chain.failure_count(), 0);
    assert_eq!(chain.total_cost_improvement(), 0);
    assert!(chain.receipts_for_optimization("nonexistent").is_empty());
    assert!(chain.failures_for_pack("nonexistent").is_empty());
}

#[test]
fn enrichment_chain_content_hash_changes_on_append() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let hash_before = chain.content_hash;
    let r = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    chain.append(r).unwrap();
    assert_ne!(chain.content_hash, hash_before);
}

#[test]
fn enrichment_chain_content_hash_changes_on_failure_record() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let hash_before = chain.content_hash;
    let f = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    chain.record_failure(f).unwrap();
    assert_ne!(chain.content_hash, hash_before);
}

#[test]
fn enrichment_chain_failure_pruning() {
    let mut chain = ReceiptChain::new("c", epoch(1)).with_max_length(3);
    for i in 0..5 {
        let f = FailureReceipt::new(
            &format!("opt-{i}"),
            "pack",
            PackVersion::CURRENT,
            vec![],
            FailureKind::MalformedOutput {
                detail: format!("err-{i}"),
            },
            None,
            false,
            epoch(1),
            i,
        );
        chain.record_failure(f).unwrap();
    }
    assert!(chain.failures.len() <= 3);
    assert_eq!(chain.failures.last().unwrap().optimization_id, "opt-4");
}

#[test]
fn enrichment_chain_record_failure_rejects_tampered_failure_hash() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let mut failure = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec!["r1".into()],
        FailureKind::MalformedOutput { detail: "x".into() },
        None,
        false,
        epoch(1),
        0,
    );
    failure.quarantined = true;

    let error = chain.record_failure(failure).unwrap_err();
    assert!(matches!(
        error,
        ReceiptChainError::FailureContentHashMismatch { .. }
    ));
}

#[test]
fn enrichment_chain_total_cost_improvement_excludes_rejected() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let r1 = make_receipt(
        1,
        "opt-1",
        None,
        epoch(1),
        0,
        vec![rule("r1", -500_000)],
        proven(),
    );
    let parent = r1.content_hash;
    chain.append(r1).unwrap();

    let r2 = make_receipt(
        2,
        "opt-2",
        Some(parent),
        epoch(1),
        0,
        vec![rule("r2", -300_000)],
        disproven(),
    );
    chain.append(r2).unwrap();

    assert_eq!(chain.total_cost_improvement(), -500_000);
}

#[test]
fn enrichment_chain_success_and_rejected_counts() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let r1 = make_receipt(1, "opt-1", None, epoch(1), 0, vec![], proven());
    let p1 = r1.content_hash;
    chain.append(r1).unwrap();

    let r2 = make_receipt(2, "opt-2", Some(p1), epoch(1), 0, vec![], disproven());
    let p2 = r2.content_hash;
    chain.append(r2).unwrap();

    let r3 = make_receipt(3, "opt-3", Some(p2), epoch(1), 0, vec![], inconclusive());
    chain.append(r3).unwrap();

    assert_eq!(chain.success_count(), 1);
    assert_eq!(chain.rejected_count(), 2);
}

#[test]
fn enrichment_chain_schema_version_on_creation() {
    let chain = ReceiptChain::new("c", epoch(1));
    assert_eq!(chain.schema_version, CHAIN_SCHEMA_VERSION);
    assert_eq!(chain.next_sequence, 1);
}

// ===========================================================================
// 8. Emitter behavior edge cases
// ===========================================================================

#[test]
fn enrichment_emitter_default_cost_model_used_when_none() {
    let mut em = emitter();
    let inp = EmitInput {
        optimization_id: "opt-dcm".into(),
        baseline_ir_hash: hash(b"b"),
        optimized_ir_hash: hash(b"o"),
        applied_rules: vec![rule("r1", -100)],
        verdict: proven(),
        cost_model_id: None,
    };
    let result = em.emit(inp);
    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.cost_model_id, "baseline-v1");
}

#[test]
fn enrichment_emitter_explicit_cost_model_overrides_default() {
    let mut em = emitter();
    let inp = EmitInput {
        optimization_id: "opt-ecm".into(),
        baseline_ir_hash: hash(b"b"),
        optimized_ir_hash: hash(b"o"),
        applied_rules: vec![rule("r1", -100)],
        verdict: proven(),
        cost_model_id: Some("explicit-cost-v9".into()),
    };
    let result = em.emit(inp);
    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.cost_model_id, "explicit-cost-v9");
}

#[test]
fn enrichment_emitter_disproven_no_rules_empty_pack() {
    let mut em = emitter();
    let inp = EmitInput {
        optimization_id: "opt-empty-rules".into(),
        baseline_ir_hash: hash(b"b"),
        optimized_ir_hash: hash(b"o"),
        applied_rules: vec![],
        verdict: disproven(),
        cost_model_id: None,
    };
    let result = em.emit(inp);
    if let EmitResult::Rejected { failure, .. } = result {
        assert_eq!(failure.pack_id, "");
        assert!(failure.attempted_rules.is_empty());
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn enrichment_emitter_inconclusive_no_rules_empty_pack() {
    let mut em = emitter();
    let inp = EmitInput {
        optimization_id: "opt-inc-empty".into(),
        baseline_ir_hash: hash(b"b"),
        optimized_ir_hash: hash(b"o"),
        applied_rules: vec![],
        verdict: inconclusive(),
        cost_model_id: None,
    };
    let result = em.emit(inp);
    if let EmitResult::Rejected { failure, .. } = result {
        assert_eq!(failure.pack_id, "");
        assert!(failure.attempted_rules.is_empty());
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn enrichment_emit_result_receipt_on_rejected() {
    let mut em = emitter();
    let result = em.emit(input("opt-rej", disproven()));
    assert!(result.receipt().is_some());
    assert!(!result.is_approved());
}

#[test]
fn enrichment_emit_result_receipt_on_quarantined_is_none() {
    let mut em = emitter();
    em.quarantine_optimization("opt-q2");
    let result = em.emit(input("opt-q2", proven()));
    assert!(result.receipt().is_none());
    assert!(!result.is_approved());
}

#[test]
fn enrichment_emitter_multiple_quarantine_lift_cycles() {
    let mut em = emitter();

    em.emit(input("opt-cycle", disproven()));
    assert!(em.is_quarantined("opt-cycle"));

    em.lift_quarantine("opt-cycle");
    let result = em.emit(input("opt-cycle", proven()));
    assert!(result.is_approved());

    em.emit(input("opt-cycle2", disproven()));
    assert!(em.is_quarantined("opt-cycle2"));
}

#[test]
fn enrichment_emitter_advance_epoch_reflected_in_receipt() {
    let mut em = emitter();
    em.advance_epoch();
    em.advance_epoch();
    assert_eq!(em.current_epoch.as_u64(), 3);

    let result = em.emit(input("opt-epoch3", proven()));
    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.epoch.as_u64(), 3);
}

#[test]
fn enrichment_emitter_tick_reflected_in_receipt() {
    let mut em = emitter();
    em.tick(1000);
    em.tick(500);
    let result = em.emit(input("opt-tick", proven()));
    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.timestamp_ticks, 1500);
}

#[test]
fn enrichment_emitter_stats_accumulate_across_emit_calls() {
    let mut em = emitter();

    let inp1 = EmitInput {
        optimization_id: "opt-s1".into(),
        baseline_ir_hash: hash(b"b"),
        optimized_ir_hash: hash(b"o"),
        applied_rules: vec![rule("r1", -100_000), rule("r2", -200_000)],
        verdict: proven(),
        cost_model_id: None,
    };
    em.emit(inp1);

    let inp2 = EmitInput {
        optimization_id: "opt-s2".into(),
        baseline_ir_hash: hash(b"b"),
        optimized_ir_hash: hash(b"o"),
        applied_rules: vec![rule("r3", -50_000)],
        verdict: proven(),
        cost_model_id: None,
    };
    em.emit(inp2);

    assert_eq!(em.stats.total_receipts, 2);
    assert_eq!(em.stats.total_proven, 2);
    assert_eq!(em.stats.total_rules_applied, 3);
    assert_eq!(em.stats.total_cost_improvement_millionths, -350_000);
}

#[test]
fn enrichment_emitter_summary_proven_rate_zero_when_no_receipts() {
    let em = emitter();
    let summary = em.summary();
    assert_eq!(summary.proven_rate_millionths, 0);
    assert_eq!(summary.total_receipts, 0);
}

#[test]
fn enrichment_emitter_summary_chain_length() {
    let mut em = emitter();
    em.emit(input("opt-1", proven()));
    em.emit(input("opt-2", proven()));
    let summary = em.summary();
    assert_eq!(summary.chain_length, 2);
}

// ===========================================================================
// 9. EmitterConfig default values
// ===========================================================================

#[test]
fn enrichment_emitter_config_default_values() {
    let cfg = EmitterConfig::default();
    assert_eq!(cfg.chain_id, "default");
    assert_eq!(cfg.signing_key.len(), 32);
    assert_eq!(cfg.max_chain_length, MAX_CHAIN_LENGTH);
    assert!(cfg.quarantine_on_first_failure);
    assert_eq!(cfg.proof_budget_ticks, 10_000_000);
    assert_eq!(cfg.default_cost_model_id, "baseline-v1");
}

#[test]
fn enrichment_emitter_stats_default_all_zeros() {
    let stats = EmitterStats::default();
    assert_eq!(stats.total_receipts, 0);
    assert_eq!(stats.total_proven, 0);
    assert_eq!(stats.total_disproven, 0);
    assert_eq!(stats.total_inconclusive, 0);
    assert_eq!(stats.total_rules_applied, 0);
    assert_eq!(stats.total_cost_improvement_millionths, 0);
    assert_eq!(stats.total_quarantined, 0);
    assert_eq!(stats.total_verifications, 0);
    assert_eq!(stats.verification_failures, 0);
}

// ===========================================================================
// 10. Proof evidence edge cases
// ===========================================================================

#[test]
fn enrichment_proof_evidence_metadata_ordering_deterministic() {
    let ev1 = ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 100)
        .with_metadata("a", "1")
        .with_metadata("b", "2");
    let ev2 = ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 100)
        .with_metadata("a", "1")
        .with_metadata("b", "2");
    assert_eq!(ev1.content_hash(), ev2.content_hash());
}

#[test]
fn enrichment_proof_evidence_with_many_metadata_entries() {
    let mut ev = ProofEvidence::new(ProofMode::Composite, hash(b"art"), 1000, 50_000);
    for i in 0..20 {
        ev = ev.with_metadata(&format!("key-{i}"), &format!("val-{i}"));
    }
    assert_eq!(ev.metadata.len(), 20);
    let h1 = ev.content_hash();
    let h2 = ev.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_proof_evidence_all_modes_produce_different_hashes() {
    let modes = [
        ProofMode::Symbolic,
        ProofMode::GoldenCorpus,
        ProofMode::DifferentialTrace,
        ProofMode::Axiomatic,
        ProofMode::Composite,
    ];
    let mut hashes = BTreeSet::new();
    for mode in modes {
        let ev = ProofEvidence::new(mode, hash(b"same"), 10, 100);
        hashes.insert(format!("{:?}", ev.content_hash()));
    }
    assert_eq!(hashes.len(), 5);
}

#[test]
fn enrichment_proof_mode_ordering_deterministic() {
    let mut modes = vec![
        ProofMode::Composite,
        ProofMode::Symbolic,
        ProofMode::Axiomatic,
        ProofMode::GoldenCorpus,
        ProofMode::DifferentialTrace,
    ];
    modes.sort();
    let mut modes2 = modes.clone();
    modes2.sort();
    assert_eq!(modes, modes2);
}

// ===========================================================================
// 11. FailureReceipt construction coverage
// ===========================================================================

#[test]
fn enrichment_failure_receipt_all_kinds_constructible() {
    let kinds = [
        FailureKind::CounterexampleFound {
            divergence: "div".into(),
        },
        FailureKind::BudgetExceeded {
            consumed_ticks: 1,
            limit_ticks: 2,
        },
        FailureKind::InterferenceDetected {
            conflicting_rules: vec!["a".into()],
        },
        FailureKind::ComplexityExceeded {
            metric: "m".into(),
            value: 10,
            limit: 5,
        },
        FailureKind::MalformedOutput {
            detail: "bad".into(),
        },
    ];
    for kind in kinds {
        let f = FailureReceipt::new(
            "opt",
            "pack",
            PackVersion::CURRENT,
            vec!["r1".into()],
            kind,
            None,
            false,
            epoch(1),
            0,
        );
        assert_eq!(f.optimization_id, "opt");
    }
}

#[test]
fn enrichment_failure_receipt_with_counterexample_hash() {
    let f = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::CounterexampleFound {
            divergence: "d".into(),
        },
        Some(hash(b"cx")),
        true,
        epoch(2),
        100,
    );
    assert!(f.counterexample_hash.is_some());
    assert!(f.quarantined);
}

#[test]
fn enrichment_failure_receipt_without_counterexample_hash() {
    let f = FailureReceipt::new(
        "opt",
        "pack",
        PackVersion::CURRENT,
        vec![],
        FailureKind::BudgetExceeded {
            consumed_ticks: 1,
            limit_ticks: 2,
        },
        None,
        false,
        epoch(1),
        0,
    );
    assert!(f.counterexample_hash.is_none());
    assert!(!f.quarantined);
}

// ===========================================================================
// 12. Chain pruning after many appends
// ===========================================================================

#[test]
fn enrichment_chain_pruning_preserves_most_recent() {
    let config = EmitterConfig {
        max_chain_length: 3,
        ..Default::default()
    };
    let mut em = ValidationReceiptEmitter::new(config, epoch(1));
    for i in 0..10 {
        em.tick(10);
        em.emit(input(&format!("opt-{i}"), proven()));
    }
    assert!(em.chain.receipts.len() <= 3);
    let last = em.chain.last_receipt().unwrap();
    assert_eq!(last.optimization_id, "opt-9");
}

#[test]
fn enrichment_chain_pruning_integrity_after_prune() {
    let config = EmitterConfig {
        max_chain_length: 5,
        ..Default::default()
    };
    let mut em = ValidationReceiptEmitter::new(config, epoch(1));
    for i in 0..20 {
        em.tick(1);
        em.emit(input(&format!("opt-{i}"), proven()));
    }
    let integrity = em.chain.verify_integrity();
    assert!(integrity.valid);
}

// ===========================================================================
// 13. Multiple simultaneous quarantines
// ===========================================================================

#[test]
fn enrichment_multiple_quarantines_tracked_independently() {
    let mut em = emitter();
    em.quarantine_optimization("opt-a");
    em.quarantine_optimization("opt-b");
    em.quarantine_optimization("opt-c");

    assert!(em.is_quarantined("opt-a"));
    assert!(em.is_quarantined("opt-b"));
    assert!(em.is_quarantined("opt-c"));
    assert!(!em.is_quarantined("opt-d"));

    em.lift_quarantine("opt-b");
    assert!(em.is_quarantined("opt-a"));
    assert!(!em.is_quarantined("opt-b"));
    assert!(em.is_quarantined("opt-c"));

    let summary = em.summary();
    assert_eq!(summary.quarantine_count, 2);
}

// ===========================================================================
// 14. Emitter full serde roundtrip with rich state
// ===========================================================================

#[test]
fn enrichment_emitter_full_serde_roundtrip() {
    let config = EmitterConfig {
        chain_id: "rich-chain".into(),
        signing_key: vec![7u8; 32],
        max_chain_length: 50,
        quarantine_on_first_failure: true,
        proof_budget_ticks: 5_000_000,
        default_cost_model_id: "rich-cost-v1".into(),
    };
    let mut em = ValidationReceiptEmitter::new(config, epoch(10));
    em.tick(100);
    em.emit(input("opt-1", proven()));
    em.tick(200);
    em.emit(input("opt-2", disproven()));
    em.tick(50);
    em.emit(input("opt-3", inconclusive()));
    em.advance_epoch();

    let json = serde_json::to_string(&em).unwrap();
    let restored: ValidationReceiptEmitter = serde_json::from_str(&json).unwrap();

    assert_eq!(em.config, restored.config);
    assert_eq!(em.chain, restored.chain);
    assert_eq!(em.quarantine, restored.quarantine);
    assert_eq!(em.current_epoch, restored.current_epoch);
    assert_eq!(em.current_ticks, restored.current_ticks);
    assert_eq!(em.stats, restored.stats);
}

// ===========================================================================
// 15. Summary field values under various conditions
// ===========================================================================

#[test]
fn enrichment_summary_chain_id_matches_config() {
    let config = EmitterConfig {
        chain_id: "my-pipeline".into(),
        ..Default::default()
    };
    let em = ValidationReceiptEmitter::new(config, epoch(1));
    let summary = em.summary();
    assert_eq!(summary.chain_id, "my-pipeline");
}

#[test]
fn enrichment_summary_current_epoch_tracks_advances() {
    let mut em = emitter();
    em.advance_epoch();
    em.advance_epoch();
    em.advance_epoch();
    let summary = em.summary();
    assert_eq!(summary.current_epoch.as_u64(), 4);
}

#[test]
fn enrichment_summary_proven_rate_millionths_accuracy() {
    let mut em = emitter();
    // 3 proven out of 4 total = 75% = 750_000 millionths
    em.emit(input("opt-1", proven()));
    em.emit(input("opt-2", proven()));
    em.emit(input("opt-3", proven()));
    em.emit(input("opt-4", disproven()));
    let summary = em.summary();
    assert_eq!(summary.proven_rate_millionths, 750_000);
}

// ===========================================================================
// 16. Quarantine interaction with emit stats
// ===========================================================================

#[test]
fn enrichment_quarantine_emit_does_not_increment_receipt_count() {
    let mut em = emitter();
    em.quarantine_optimization("opt-blocked");
    let result = em.emit(input("opt-blocked", proven()));
    assert!(matches!(result, EmitResult::Quarantined { .. }));
    assert_eq!(em.stats.total_receipts, 0);
    assert_eq!(em.stats.total_proven, 0);
}

#[test]
fn enrichment_quarantine_reason_message() {
    let mut em = emitter();
    em.quarantine_optimization("opt-q");
    let result = em.emit(input("opt-q", proven()));
    if let EmitResult::Quarantined {
        optimization_id,
        reason,
    } = result
    {
        assert_eq!(optimization_id, "opt-q");
        assert!(!reason.is_empty());
    } else {
        panic!("expected Quarantined");
    }
}

// ===========================================================================
// 17. Verification stats tracking
// ===========================================================================

#[test]
fn enrichment_verify_receipt_increments_stats() {
    let mut em = emitter();
    let result = em.emit(input("opt-v", proven()));
    let receipt = result.receipt().unwrap().clone();

    assert!(em.verify_receipt(&receipt));
    assert_eq!(em.stats.total_verifications, 1);
    assert_eq!(em.stats.verification_failures, 0);

    // Verify again
    assert!(em.verify_receipt(&receipt));
    assert_eq!(em.stats.total_verifications, 2);
    assert_eq!(em.stats.verification_failures, 0);
}

#[test]
fn enrichment_verify_tampered_receipt_increments_failure_count() {
    let mut em = emitter();
    let result = em.emit(input("opt-tamper", proven()));
    let mut tampered = result.receipt().unwrap().clone();
    tampered.cost_model_id = "tampered-cost-model".into();

    assert!(!em.verify_receipt(&tampered));
    assert_eq!(em.stats.total_verifications, 1);
    assert_eq!(em.stats.verification_failures, 1);
}

// ===========================================================================
// 18. Chain serde with failures and receipts
// ===========================================================================

#[test]
fn enrichment_chain_with_failures_serde_roundtrip() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let r = make_receipt(1, "opt", None, epoch(1), 0, vec![], proven());
    chain.append(r).unwrap();

    let f = FailureReceipt::new(
        "opt-f",
        "pack",
        PackVersion::CURRENT,
        vec!["r1".into()],
        FailureKind::CounterexampleFound {
            divergence: "d".into(),
        },
        None,
        false,
        epoch(1),
        100,
    );
    chain.record_failure(f).unwrap();

    let json = serde_json::to_string(&chain).unwrap();
    let restored: ReceiptChain = serde_json::from_str(&json).unwrap();
    assert_eq!(chain, restored);
    assert_eq!(restored.receipts.len(), 1);
    assert_eq!(restored.failures.len(), 1);
}

// ===========================================================================
// 19. Emitter summary integrity issues count
// ===========================================================================

#[test]
fn enrichment_summary_with_no_integrity_issues() {
    let mut em = emitter();
    em.emit(input("opt-1", proven()));
    em.emit(input("opt-2", proven()));
    let summary = em.summary();
    assert!(summary.chain_valid);
    assert_eq!(summary.chain_integrity_issues, 0);
}

// ===========================================================================
// 20. Disproven failure receipt includes counterexample hash from verdict
// ===========================================================================

#[test]
fn enrichment_disproven_failure_receipt_has_counterexample() {
    let mut em = emitter();
    let result = em.emit(input("opt-cx", disproven()));
    if let EmitResult::Rejected { failure, .. } = result {
        assert!(failure.counterexample_hash.is_some());
        assert!(matches!(
            failure.failure_kind,
            FailureKind::CounterexampleFound { .. }
        ));
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn enrichment_inconclusive_failure_receipt_no_counterexample() {
    let mut em = emitter();
    let result = em.emit(input("opt-inc", inconclusive()));
    if let EmitResult::Rejected { failure, .. } = result {
        assert!(failure.counterexample_hash.is_none());
        assert!(matches!(
            failure.failure_kind,
            FailureKind::BudgetExceeded { .. }
        ));
    } else {
        panic!("expected Rejected");
    }
}
