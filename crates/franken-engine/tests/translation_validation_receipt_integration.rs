//! Integration tests for translation_validation_receipt module.
//!
//! Bead: bd-1lsy.7.7.2 [RGC-607B]

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy
)]

use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
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
        pack_id: "integration-pack".into(),
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
        pack_id: "integration-pack".into(),
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
        evidence: ProofEvidence::new(
            ProofMode::Symbolic,
            hash(b"proof"),
            50,
            2000,
        ),
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

fn default_config() -> EmitterConfig {
    EmitterConfig::default()
}

fn emitter() -> ValidationReceiptEmitter {
    ValidationReceiptEmitter::new(default_config(), epoch(1))
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

fn multi_rule_input(opt_id: &str, verdict: ReceiptVerdict) -> EmitInput {
    EmitInput {
        optimization_id: opt_id.into(),
        baseline_ir_hash: hash(b"baseline-multi"),
        optimized_ir_hash: hash(b"optimized-multi"),
        applied_rules: vec![
            rule("r-fold-1", -300_000),
            dce_rule("r-dce-1", -150_000),
            rule("r-cse-1", -50_000),
        ],
        verdict,
        cost_model_id: Some("advanced-cost-v2".into()),
    }
}

// ---------------------------------------------------------------------------
// E2E: happy-path proven optimization
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_proven_optimization_flow() {
    let mut em = emitter();
    let result = em.emit(input("opt-happy", proven()));
    assert!(result.is_approved());

    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.optimization_id, "opt-happy");
    assert!(receipt.permits_activation());
    assert!(receipt.verify_signature(&em.config.signing_key));

    let summary = em.summary();
    assert_eq!(summary.total_receipts, 1);
    assert_eq!(summary.total_proven, 1);
    assert_eq!(summary.proven_rate_millionths, 1_000_000);
    assert!(summary.chain_valid);
}

// ---------------------------------------------------------------------------
// E2E: disproven → quarantine → lift → reprove
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_disproven_quarantine_lift_reprove() {
    let mut em = emitter();

    // Step 1: disproven → quarantined
    let result = em.emit(input("opt-flaky", disproven()));
    assert!(!result.is_approved());
    assert!(em.is_quarantined("opt-flaky"));

    // Step 2: quarantined → blocked
    let result2 = em.emit(input("opt-flaky", proven()));
    assert!(matches!(result2, EmitResult::Quarantined { .. }));

    // Step 3: lift quarantine
    assert!(em.lift_quarantine("opt-flaky"));
    assert!(!em.is_quarantined("opt-flaky"));

    // Step 4: reprove → approved
    let result3 = em.emit(input("opt-flaky", proven()));
    assert!(result3.is_approved());
}

// ---------------------------------------------------------------------------
// E2E: multiple optimizations with mixed verdicts
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_mixed_verdicts_pipeline() {
    let mut em = emitter();
    em.tick(100);

    // Proven
    em.emit(input("opt-1", proven()));
    em.tick(100);

    // Another proven
    em.emit(input("opt-2", proven()));
    em.tick(100);

    // Disproven
    em.emit(input("opt-3", disproven()));
    em.tick(100);

    // Inconclusive
    em.emit(input("opt-4", inconclusive()));

    let summary = em.summary();
    assert_eq!(summary.total_receipts, 4);
    assert_eq!(summary.total_proven, 2);
    assert_eq!(summary.total_disproven, 1);
    assert_eq!(summary.total_inconclusive, 1);
    assert_eq!(summary.proven_rate_millionths, 500_000); // 50%
    assert_eq!(summary.quarantine_count, 1); // only disproven gets quarantined
}

// ---------------------------------------------------------------------------
// E2E: multi-rule receipt with cost tracking
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_multi_rule_cost_tracking() {
    let mut em = emitter();
    let result = em.emit(multi_rule_input("opt-multi", proven()));

    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.rule_count(), 3);
    assert_eq!(receipt.total_cost_delta_millionths, -500_000); // -300k + -150k + -50k
    assert!(receipt.is_net_improvement());
    assert_eq!(receipt.rewrite_categories.len(), 2); // AlgebraicSimplification + DeadCodeElimination
    assert_eq!(receipt.cost_model_id, "advanced-cost-v2");

    assert_eq!(em.stats.total_rules_applied, 3);
    assert_eq!(em.stats.total_cost_improvement_millionths, -500_000);
}

// ---------------------------------------------------------------------------
// Receipt chain integrity
// ---------------------------------------------------------------------------

#[test]
fn test_chain_integrity_after_multiple_appends() {
    let mut em = emitter();
    for i in 0..10 {
        em.tick(100);
        em.emit(input(&format!("opt-{i}"), proven()));
    }
    let integrity = em.chain.verify_integrity();
    assert!(integrity.valid);
    assert_eq!(integrity.receipt_count, 10);
    assert!(integrity.issues.is_empty());
}

#[test]
fn test_chain_parent_hash_linkage() {
    let mut em = emitter();
    em.emit(input("opt-1", proven()));
    em.emit(input("opt-2", proven()));
    em.emit(input("opt-3", proven()));

    let receipts = &em.chain.receipts;
    // First receipt has no parent
    assert!(receipts[0].parent_hash.is_none());
    // Second receipt links to first
    assert_eq!(receipts[1].parent_hash.as_ref().unwrap(), &receipts[0].content_hash);
    // Third links to second
    assert_eq!(receipts[2].parent_hash.as_ref().unwrap(), &receipts[1].content_hash);
}

#[test]
fn test_chain_sequence_monotonicity() {
    let mut em = emitter();
    for i in 0..5 {
        em.emit(input(&format!("opt-{i}"), proven()));
    }
    for i in 1..em.chain.receipts.len() {
        assert!(em.chain.receipts[i].sequence > em.chain.receipts[i - 1].sequence);
    }
}

// ---------------------------------------------------------------------------
// Chain pruning
// ---------------------------------------------------------------------------

#[test]
fn test_chain_pruning_preserves_recent() {
    let config = EmitterConfig {
        max_chain_length: 5,
        ..Default::default()
    };
    let mut em = ValidationReceiptEmitter::new(config, epoch(1));

    for i in 0..20 {
        em.tick(10);
        em.emit(input(&format!("opt-{i}"), proven()));
    }

    assert!(em.chain.receipts.len() <= 5);
    // Most recent should be the last one emitted
    let last = em.chain.last_receipt().unwrap();
    assert_eq!(last.optimization_id, "opt-19");
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

#[test]
fn test_signature_verification_across_chain() {
    let mut em = emitter();
    for i in 0..5 {
        em.emit(input(&format!("opt-{i}"), proven()));
    }

    for receipt in &em.chain.receipts {
        assert!(em.verify_receipt(receipt));
    }
    assert_eq!(em.stats.total_verifications, 5);
    assert_eq!(em.stats.verification_failures, 0);
}

#[test]
fn test_tampered_receipt_fails_verification() {
    let mut em = emitter();
    let result = em.emit(input("opt-tamper", proven()));
    let mut tampered = result.receipt().unwrap().clone();
    tampered.optimization_id = "opt-CHANGED".into();
    // Content hash is still the original — but signing preimage uses content_hash,
    // so the signature should still fail because the receipt content was tampered
    // before content_hash computation (in this case content_hash was already baked in).
    // The verification checks signature against the content_hash, so it should still pass
    // unless we change the content_hash itself.
    tampered.content_hash = hash(b"tampered-hash");
    assert!(!em.verify_receipt(&tampered));
    assert_eq!(em.stats.verification_failures, 1);
}

// ---------------------------------------------------------------------------
// Quarantine behavior
// ---------------------------------------------------------------------------

#[test]
fn test_quarantine_on_disproven() {
    let mut em = emitter();
    em.emit(input("opt-bad", disproven()));
    assert!(em.is_quarantined("opt-bad"));
    assert_eq!(em.stats.total_quarantined, 1);
}

#[test]
fn test_no_quarantine_on_inconclusive() {
    let mut em = emitter();
    em.emit(input("opt-timeout", inconclusive()));
    assert!(!em.is_quarantined("opt-timeout"));
}

#[test]
fn test_quarantine_disabled_by_config() {
    let config = EmitterConfig {
        quarantine_on_first_failure: false,
        ..Default::default()
    };
    let mut em = ValidationReceiptEmitter::new(config, epoch(1));
    em.emit(input("opt-bad", disproven()));
    assert!(!em.is_quarantined("opt-bad"));
}

#[test]
fn test_manual_quarantine_and_lift() {
    let mut em = emitter();
    em.quarantine_optimization("opt-manual");
    assert!(em.is_quarantined("opt-manual"));

    // Can't submit while quarantined
    let r = em.emit(input("opt-manual", proven()));
    assert!(matches!(r, EmitResult::Quarantined { .. }));

    // Lift and retry
    em.lift_quarantine("opt-manual");
    let r2 = em.emit(input("opt-manual", proven()));
    assert!(r2.is_approved());
}

#[test]
fn test_lift_nonexistent_quarantine() {
    let mut em = emitter();
    assert!(!em.lift_quarantine("never-quarantined"));
}

// ---------------------------------------------------------------------------
// Failure receipts
// ---------------------------------------------------------------------------

#[test]
fn test_failure_receipt_on_disproven() {
    let mut em = emitter();
    let result = em.emit(input("opt-fail", disproven()));
    if let EmitResult::Rejected { failure, .. } = result {
        assert_eq!(failure.optimization_id, "opt-fail");
        assert!(failure.quarantined);
        assert!(matches!(failure.failure_kind, FailureKind::CounterexampleFound { .. }));
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn test_failure_receipt_on_inconclusive() {
    let mut em = emitter();
    let result = em.emit(input("opt-inc", inconclusive()));
    if let EmitResult::Rejected { failure, .. } = result {
        assert_eq!(failure.optimization_id, "opt-inc");
        assert!(!failure.quarantined);
        assert!(matches!(failure.failure_kind, FailureKind::BudgetExceeded { .. }));
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn test_failure_receipts_accumulated() {
    let mut em = emitter();
    em.emit(input("opt-1", disproven()));
    // Need new opt_id since opt-1 is quarantined
    em.emit(input("opt-2", inconclusive()));
    assert_eq!(em.chain.failure_count(), 2);
}

// ---------------------------------------------------------------------------
// Epoch and tick management
// ---------------------------------------------------------------------------

#[test]
fn test_epoch_advancement() {
    let mut em = emitter();
    assert_eq!(em.current_epoch.as_u64(), 1);
    em.advance_epoch();
    assert_eq!(em.current_epoch.as_u64(), 2);

    em.emit(input("opt-e2", proven()));
    let receipt = em.chain.last_receipt().unwrap();
    assert_eq!(receipt.epoch.as_u64(), 2);
}

#[test]
fn test_tick_tracking() {
    let mut em = emitter();
    em.tick(500);
    em.emit(input("opt-t1", proven()));
    let receipt = em.chain.last_receipt().unwrap();
    assert_eq!(receipt.timestamp_ticks, 500);

    em.tick(300);
    em.emit(input("opt-t2", proven()));
    let receipt2 = em.chain.last_receipt().unwrap();
    assert_eq!(receipt2.timestamp_ticks, 800);
}

// ---------------------------------------------------------------------------
// Proof evidence
// ---------------------------------------------------------------------------

#[test]
fn test_proof_evidence_metadata() {
    let ev = ProofEvidence::new(ProofMode::GoldenCorpus, hash(b"corpus"), 1000, 50_000)
        .with_metadata("corpus_size", "5000")
        .with_metadata("coverage", "98.5%");
    assert_eq!(ev.metadata.len(), 2);
    assert_eq!(ev.metadata.get("corpus_size").unwrap(), "5000");
}

#[test]
fn test_proof_evidence_hash_stability() {
    let ev1 = ProofEvidence::new(ProofMode::Axiomatic, hash(b"x"), 10, 100);
    let ev2 = ProofEvidence::new(ProofMode::Axiomatic, hash(b"x"), 10, 100);
    assert_eq!(ev1.content_hash(), ev2.content_hash());
}

#[test]
fn test_proof_evidence_hash_sensitivity() {
    let ev1 = ProofEvidence::new(ProofMode::Symbolic, hash(b"x"), 10, 100);
    let ev2 = ProofEvidence::new(ProofMode::Symbolic, hash(b"y"), 10, 100);
    assert_ne!(ev1.content_hash(), ev2.content_hash());
}

// ---------------------------------------------------------------------------
// Applied rule records
// ---------------------------------------------------------------------------

#[test]
fn test_rule_significance_threshold() {
    let big = rule("r-big", -100_000); // above threshold
    assert!(big.is_significant_improvement());

    let small = rule("r-small", -10_000); // below threshold
    assert!(small.is_improvement());
    assert!(!small.is_significant_improvement());

    let neutral = rule("r-neutral", 0);
    assert!(!neutral.is_improvement());

    let worse = rule("r-worse", 50_000); // cost increase
    assert!(!worse.is_improvement());
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_serde_receipt_roundtrip() {
    let mut em = emitter();
    em.emit(input("opt-serde", proven()));
    let receipt = em.chain.last_receipt().unwrap();
    let json = serde_json::to_string(receipt).unwrap();
    let restored: TranslationValidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, &restored);
}

#[test]
fn test_serde_failure_receipt_roundtrip() {
    let fr = FailureReceipt::new(
        "opt-f", "pack-1", PackVersion::CURRENT,
        vec!["r1".into(), "r2".into()],
        FailureKind::InterferenceDetected {
            conflicting_rules: vec!["r1".into(), "r2".into()],
        },
        None, true, epoch(5), 12345,
    );
    let json = serde_json::to_string(&fr).unwrap();
    let restored: FailureReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(fr, restored);
}

#[test]
fn test_serde_chain_roundtrip() {
    let mut em = emitter();
    em.emit(input("opt-1", proven()));
    em.emit(input("opt-2", proven()));
    em.emit(input("opt-3", disproven()));

    let json = serde_json::to_string(&em.chain).unwrap();
    let restored: ReceiptChain = serde_json::from_str(&json).unwrap();
    assert_eq!(em.chain, restored);
}

#[test]
fn test_serde_emitter_roundtrip() {
    let mut em = emitter();
    em.emit(input("opt-1", proven()));
    em.tick(500);
    em.emit(input("opt-2", disproven()));

    let json = serde_json::to_string(&em).unwrap();
    let restored: ValidationReceiptEmitter = serde_json::from_str(&json).unwrap();
    assert_eq!(em.stats.total_receipts, restored.stats.total_receipts);
    assert_eq!(em.quarantine, restored.quarantine);
    assert_eq!(em.current_ticks, restored.current_ticks);
}

#[test]
fn test_serde_verdict_all_variants() {
    let verdicts = vec![proven(), disproven(), inconclusive()];
    for v in verdicts {
        let json = serde_json::to_string(&v).unwrap();
        let restored: ReceiptVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn test_serde_failure_kind_all_variants() {
    let kinds = vec![
        FailureKind::CounterexampleFound { divergence: "x diverges".into() },
        FailureKind::BudgetExceeded { consumed_ticks: 999, limit_ticks: 1000 },
        FailureKind::InterferenceDetected { conflicting_rules: vec!["a".into(), "b".into()] },
        FailureKind::ComplexityExceeded { metric: "ir_nodes".into(), value: 100000, limit: 50000 },
        FailureKind::MalformedOutput { detail: "dangling phi node".into() },
    ];
    for k in kinds {
        let json = serde_json::to_string(&k).unwrap();
        let restored: FailureKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, restored);
    }
}

#[test]
fn test_serde_proof_mode_all_variants() {
    let modes = vec![
        ProofMode::Symbolic,
        ProofMode::GoldenCorpus,
        ProofMode::DifferentialTrace,
        ProofMode::Axiomatic,
        ProofMode::Composite,
    ];
    for m in modes {
        let json = serde_json::to_string(&m).unwrap();
        let restored: ProofMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }
}

// ---------------------------------------------------------------------------
// Chain error handling
// ---------------------------------------------------------------------------

#[test]
fn test_chain_rejects_wrong_parent() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let r1 = TranslationValidationReceipt::new(
        1, "opt-1", None, epoch(1), 0,
        hash(b"b"), hash(b"o"), vec![], proven(), "cm",
    );
    chain.append(r1).unwrap();

    let r2 = TranslationValidationReceipt::new(
        2, "opt-2", Some(hash(b"wrong-parent")), epoch(1), 0,
        hash(b"b"), hash(b"o"), vec![], proven(), "cm",
    );
    let err = chain.append(r2).unwrap_err();
    assert!(matches!(err, ReceiptChainError::ParentHashMismatch { .. }));
}

#[test]
fn test_chain_rejects_sequence_gap() {
    let mut chain = ReceiptChain::new("c", epoch(1));
    let r = TranslationValidationReceipt::new(
        99, "opt-1", None, epoch(1), 0,
        hash(b"b"), hash(b"o"), vec![], proven(), "cm",
    );
    let err = chain.append(r).unwrap_err();
    assert!(matches!(err, ReceiptChainError::SequenceGap { expected: 1, actual: 99 }));
}

#[test]
fn test_chain_error_display() {
    let e = ReceiptChainError::SequenceGap { expected: 5, actual: 10 };
    let s = e.to_string();
    assert!(s.contains("sequence gap"));
    assert!(s.contains("5"));
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic() {
    let r1 = TranslationValidationReceipt::new(
        1, "opt-det", None, epoch(1), 500,
        hash(b"baseline"), hash(b"optimized"),
        vec![rule("r1", -100), rule("r2", -200)],
        proven(), "cm-v1",
    );
    let r2 = TranslationValidationReceipt::new(
        1, "opt-det", None, epoch(1), 500,
        hash(b"baseline"), hash(b"optimized"),
        vec![rule("r1", -100), rule("r2", -200)],
        proven(), "cm-v1",
    );
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipt_hash_changes_with_rules() {
    let r1 = TranslationValidationReceipt::new(
        1, "opt", None, epoch(1), 0,
        hash(b"b"), hash(b"o"),
        vec![rule("r1", -100)],
        proven(), "cm",
    );
    let r2 = TranslationValidationReceipt::new(
        1, "opt", None, epoch(1), 0,
        hash(b"b"), hash(b"o"),
        vec![rule("r2", -100)], // different rule ID
        proven(), "cm",
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Summary statistics
// ---------------------------------------------------------------------------

#[test]
fn test_summary_cost_improvement() {
    let mut em = emitter();
    let mut inp1 = input("opt-1", proven());
    inp1.applied_rules = vec![rule("r1", -1_000_000)]; // -1.0
    em.emit(inp1);

    let mut inp2 = input("opt-2", proven());
    inp2.applied_rules = vec![rule("r2", -500_000)]; // -0.5
    em.emit(inp2);

    let summary = em.summary();
    assert_eq!(summary.total_cost_improvement_millionths, -1_500_000);
}

#[test]
fn test_summary_with_failures() {
    let mut em = emitter();
    em.emit(input("opt-1", proven()));
    em.emit(input("opt-2", disproven()));
    em.emit(input("opt-3", inconclusive()));

    let summary = em.summary();
    assert_eq!(summary.total_receipts, 3);
    assert_eq!(summary.chain_integrity_issues, 0);
    assert_eq!(summary.quarantine_count, 1);
}

// ---------------------------------------------------------------------------
// Receipts for specific optimizations
// ---------------------------------------------------------------------------

#[test]
fn test_chain_query_by_optimization() {
    let mut em = emitter();
    em.emit(input("opt-target", proven()));
    em.emit(input("opt-other", proven()));
    em.emit(input("opt-target", proven())); // same opt_id again

    let target_receipts = em.chain.receipts_for_optimization("opt-target");
    assert_eq!(target_receipts.len(), 2);
}

#[test]
fn test_chain_query_failures_by_pack() {
    let mut em = emitter();
    em.emit(input("opt-1", disproven())); // pack from rule is "integration-pack"

    let failures = em.chain.failures_for_pack("integration-pack");
    assert_eq!(failures.len(), 1);
    assert!(em.chain.failures_for_pack("other-pack").is_empty());
}

// ---------------------------------------------------------------------------
// Proven sound rule tracking
// ---------------------------------------------------------------------------

#[test]
fn test_all_rules_proven_sound() {
    let receipt = TranslationValidationReceipt::new(
        1, "opt", None, epoch(1), 0,
        hash(b"b"), hash(b"o"),
        vec![rule("r1", -100), rule("r2", -200)],
        proven(), "cm",
    );
    assert!(receipt.all_rules_proven_sound());
    assert_eq!(receipt.proven_sound_rule_count(), 2);
}

#[test]
fn test_mixed_proven_sound_rules() {
    let mut unproven = rule("r2", -200);
    unproven.rule_proven_sound = false;
    let receipt = TranslationValidationReceipt::new(
        1, "opt", None, epoch(1), 0,
        hash(b"b"), hash(b"o"),
        vec![rule("r1", -100), unproven],
        proven(), "cm",
    );
    assert!(!receipt.all_rules_proven_sound());
    assert_eq!(receipt.proven_sound_rule_count(), 1);
}

// ---------------------------------------------------------------------------
// Schema versions
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_schema_version() {
    let receipt = TranslationValidationReceipt::new(
        1, "opt", None, epoch(1), 0,
        hash(b"b"), hash(b"o"), vec![], proven(), "cm",
    );
    assert_eq!(receipt.schema_version, RECEIPT_SCHEMA_VERSION);
}

#[test]
fn test_chain_schema_version() {
    let chain = ReceiptChain::new("c", epoch(1));
    assert_eq!(chain.schema_version, CHAIN_SCHEMA_VERSION);
}

#[test]
fn test_summary_schema_version() {
    let em = emitter();
    let summary = em.summary();
    assert_eq!(summary.schema_version, SUMMARY_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_constants() {
    assert_eq!(COMPONENT, "translation_validation_receipt");
    assert_eq!(BEAD_ID, "bd-1lsy.7.7.2");
    assert!(MAX_CHAIN_LENGTH > 0);
    assert!(MAX_RULES_PER_RECEIPT > 0);
    assert!(SIGNIFICANT_IMPROVEMENT_THRESHOLD > 0);
}

// ---------------------------------------------------------------------------
// Stress: large chain
// ---------------------------------------------------------------------------

#[test]
fn test_large_chain_integrity() {
    let mut em = emitter();
    for i in 0..100 {
        em.tick(1);
        em.emit(input(&format!("opt-{i}"), proven()));
    }
    let integrity = em.chain.verify_integrity();
    assert!(integrity.valid);
    assert_eq!(em.stats.total_receipts, 100);
    assert_eq!(em.stats.total_proven, 100);
}

// ---------------------------------------------------------------------------
// Edge: empty rules
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_with_no_rules() {
    let mut em = emitter();
    let inp = EmitInput {
        optimization_id: "opt-empty".into(),
        baseline_ir_hash: hash(b"b"),
        optimized_ir_hash: hash(b"o"),
        applied_rules: vec![],
        verdict: proven(),
        cost_model_id: None,
    };
    let result = em.emit(inp);
    assert!(result.is_approved());
    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.rule_count(), 0);
    assert_eq!(receipt.total_cost_delta_millionths, 0);
    assert!(!receipt.is_net_improvement());
}

// ---------------------------------------------------------------------------
// Display formatting
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_display_formatting() {
    assert!(proven().to_string().starts_with("PROVEN"));
    assert!(disproven().to_string().starts_with("DISPROVEN"));
    assert!(inconclusive().to_string().starts_with("INCONCLUSIVE"));
}

#[test]
fn test_failure_kind_display_formatting() {
    let k = FailureKind::CounterexampleFound { divergence: "x!=y".into() };
    assert!(k.to_string().contains("counterexample"));

    let k2 = FailureKind::MalformedOutput { detail: "bad cfg".into() };
    assert!(k2.to_string().contains("malformed"));
}

#[test]
fn test_proof_mode_display_formatting() {
    assert_eq!(ProofMode::Symbolic.to_string(), "symbolic");
    assert_eq!(ProofMode::GoldenCorpus.to_string(), "golden_corpus");
    assert_eq!(ProofMode::DifferentialTrace.to_string(), "differential_trace");
    assert_eq!(ProofMode::Axiomatic.to_string(), "axiomatic");
    assert_eq!(ProofMode::Composite.to_string(), "composite");
}
