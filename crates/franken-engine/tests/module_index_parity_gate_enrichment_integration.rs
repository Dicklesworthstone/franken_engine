#![allow(clippy::too_many_arguments)]

//! Enrichment integration tests for `module_index_parity_gate`.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_index_parity_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn matching_result(spec: &str) -> SpecifierResult {
    SpecifierResult {
        specifier: spec.to_string(),
        matches: true,
        baseline_path: Some(format!("/node_modules/{spec}/index.js")),
        index_path: Some(format!("/node_modules/{spec}/index.js")),
    }
}

fn mismatching_result(spec: &str) -> SpecifierResult {
    SpecifierResult {
        specifier: spec.to_string(),
        matches: false,
        baseline_path: Some(format!("/node_modules/{spec}/index.js")),
        index_path: Some(format!("/node_modules/{spec}/main.js")),
    }
}

fn full_parity_evidence(n: u64) -> ParityEvidence {
    let results: Vec<_> = (0..n)
        .map(|i| matching_result(&format!("pkg-{i:04}")))
        .collect();
    ParityEvidence::from_results("ev-parity", "test-cohort", results)
}

fn partial_parity_evidence(total: u64, mismatches: u64) -> ParityEvidence {
    let mut results: Vec<_> = (0..total.saturating_sub(mismatches))
        .map(|i| matching_result(&format!("pkg-{i:04}")))
        .collect();
    for i in 0..mismatches {
        results.push(mismatching_result(&format!("bad-{i:04}")));
    }
    ParityEvidence::from_results("ev-parity", "test-cohort", results)
}

fn good_cold_start() -> ColdStartEvidence {
    ColdStartEvidence::new("ev-cold", 1_000_000, 950_000, 200)
}

fn regressing_cold_start() -> ColdStartEvidence {
    ColdStartEvidence::new("ev-cold", 1_000_000, 1_200_000, 200)
}

fn insufficient_cold_start() -> ColdStartEvidence {
    ColdStartEvidence::new("ev-cold", 1_000_000, 950_000, 5)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_valid() {
    assert!(SCHEMA_VERSION.contains("module-index-parity-gate"));
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(COMPONENT, "module_index_parity_gate");
    assert_eq!(POLICY_ID, "RGC-406C");
    assert_eq!(MILLIONTHS, 1_000_000);
    assert_eq!(DEFAULT_PARITY_THRESHOLD_MILLIONTHS, 1_000_000);
    assert_eq!(DEFAULT_COLD_START_BUDGET_MILLIONTHS, 50_000);
    assert_eq!(DEFAULT_MIN_SPECIFIER_COUNT, 100);
    assert_eq!(MAX_CONSECUTIVE_ROLLBACKS, 3);
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

#[test]
fn parity_verdict_shippable() {
    assert!(ParityVerdict::FullParity.is_shippable());
    assert!(!ParityVerdict::PartialParity.is_shippable());
    assert!(!ParityVerdict::NoParity.is_shippable());
    assert!(!ParityVerdict::InsufficientData.is_shippable());
}

#[test]
fn parity_verdict_display_distinct() {
    let displays: BTreeSet<String> = [
        ParityVerdict::FullParity,
        ParityVerdict::PartialParity,
        ParityVerdict::NoParity,
        ParityVerdict::InsufficientData,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn parity_verdict_serde_roundtrip() {
    for v in [
        ParityVerdict::FullParity,
        ParityVerdict::PartialParity,
        ParityVerdict::NoParity,
        ParityVerdict::InsufficientData,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// ColdStartVerdict
// ---------------------------------------------------------------------------

#[test]
fn cold_start_verdict_acceptable() {
    assert!(ColdStartVerdict::WithinBudget.is_acceptable());
    assert!(!ColdStartVerdict::Regression.is_acceptable());
    assert!(!ColdStartVerdict::InsufficientSamples.is_acceptable());
}

#[test]
fn cold_start_verdict_serde_roundtrip() {
    for v in [
        ColdStartVerdict::WithinBudget,
        ColdStartVerdict::Regression,
        ColdStartVerdict::InsufficientSamples,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ColdStartVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

#[test]
fn gate_decision_is_approved() {
    assert!(GateDecision::Approved.is_approved());
    assert!(!GateDecision::Denied.is_approved());
    assert!(!GateDecision::RolledBack.is_approved());
    assert!(!GateDecision::Inconclusive.is_approved());
}

#[test]
fn gate_decision_serde_roundtrip() {
    for v in [
        GateDecision::Approved,
        GateDecision::Denied,
        GateDecision::RolledBack,
        GateDecision::Inconclusive,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// BlockingReason
// ---------------------------------------------------------------------------

#[test]
fn blocking_reason_display_parity() {
    let r = BlockingReason::ParityMismatch {
        mismatch_count: 5,
        total_tested: 100,
    };
    assert!(r.to_string().contains("5/100"));
}

#[test]
fn blocking_reason_display_cold_start() {
    let r = BlockingReason::ColdStartRegression {
        regression_millionths: 100_000,
        budget_millionths: 50_000,
    };
    assert!(r.to_string().contains("100000>50000"));
}

#[test]
fn blocking_reason_display_lockout() {
    let r = BlockingReason::RollbackLockout {
        consecutive_rollbacks: 3,
    };
    assert!(r.to_string().contains("3"));
}

#[test]
fn blocking_reason_serde_roundtrip() {
    let reasons = [
        BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 100,
        },
        BlockingReason::ColdStartRegression {
            regression_millionths: 100_000,
            budget_millionths: 50_000,
        },
        BlockingReason::InsufficientCoverage {
            sampled: 10,
            minimum_required: 100,
        },
        BlockingReason::RollbackLockout {
            consecutive_rollbacks: 3,
        },
        BlockingReason::CooldownActive {
            remaining_ns: 5_000_000_000,
        },
    ];
    for r in reasons {
        let json = serde_json::to_string(&r).unwrap();
        let back: BlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ---------------------------------------------------------------------------
// SpecifierResult
// ---------------------------------------------------------------------------

#[test]
fn specifier_result_hash_deterministic() {
    let a = matching_result("react");
    let b = matching_result("react");
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn specifier_result_different_paths_different_hash() {
    let a = matching_result("react");
    let b = mismatching_result("react");
    assert_ne!(a.content_hash(), b.content_hash());
}

// ---------------------------------------------------------------------------
// ParityEvidence
// ---------------------------------------------------------------------------

#[test]
fn parity_evidence_full_match() {
    let ev = full_parity_evidence(200);
    assert_eq!(ev.match_count, 200);
    assert_eq!(ev.mismatch_count, 0);
    assert_eq!(ev.parity_ratio_millionths, MILLIONTHS);
}

#[test]
fn parity_evidence_partial_match() {
    let ev = partial_parity_evidence(200, 10);
    assert_eq!(ev.match_count, 190);
    assert_eq!(ev.mismatch_count, 10);
    assert!(ev.parity_ratio_millionths < MILLIONTHS);
    assert!(ev.parity_ratio_millionths > 0);
}

#[test]
fn parity_evidence_empty() {
    let ev = ParityEvidence::from_results("ev", "empty", vec![]);
    assert_eq!(ev.total_tested, 0);
    assert_eq!(ev.parity_ratio_millionths, 0);
}

#[test]
fn parity_evidence_seal_deterministic() {
    let a = full_parity_evidence(200);
    let b = full_parity_evidence(200);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn parity_evidence_serde_roundtrip() {
    let ev = full_parity_evidence(10);
    let json = serde_json::to_string(&ev).unwrap();
    let back: ParityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// ColdStartEvidence
// ---------------------------------------------------------------------------

#[test]
fn cold_start_speedup() {
    let ev = ColdStartEvidence::new("ev", 1_000_000, 800_000, 100);
    assert!(ev.is_speedup);
    assert_eq!(ev.regression_millionths, 0);
}

#[test]
fn cold_start_regression() {
    let ev = ColdStartEvidence::new("ev", 1_000_000, 1_200_000, 100);
    assert!(!ev.is_speedup);
    assert_eq!(ev.regression_millionths, 200_000);
}

#[test]
fn cold_start_equal() {
    let ev = ColdStartEvidence::new("ev", 1_000_000, 1_000_000, 100);
    assert!(ev.is_speedup);
    assert_eq!(ev.regression_millionths, 0);
}

#[test]
fn cold_start_zero_baseline() {
    let ev = ColdStartEvidence::new("ev", 0, 100, 100);
    assert_eq!(ev.regression_millionths, 0);
}

#[test]
fn cold_start_seal_deterministic() {
    let a = good_cold_start();
    let b = good_cold_start();
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn cold_start_serde_roundtrip() {
    let ev = good_cold_start();
    let json = serde_json::to_string(&ev).unwrap();
    let back: ColdStartEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn gate_config_default() {
    let c = GateConfig::default();
    assert_eq!(c.parity_threshold_millionths, MILLIONTHS);
    assert_eq!(c.cold_start_budget_millionths, 50_000);
    assert!(c.fail_closed);
}

#[test]
fn gate_config_builders() {
    let c = GateConfig::default()
        .with_parity_threshold(900_000)
        .with_cold_start_budget(100_000)
        .fail_open();
    assert_eq!(c.parity_threshold_millionths, 900_000);
    assert_eq!(c.cold_start_budget_millionths, 100_000);
    assert!(!c.fail_closed);
}

#[test]
fn gate_config_serde_roundtrip() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// ModuleIndexParityGate
// ---------------------------------------------------------------------------

#[test]
fn gate_new_initial_state() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    assert_eq!(g.evaluation_count(), 0);
    assert_eq!(g.approved_count(), 0);
    assert_eq!(g.denied_count(), 0);
    assert!(!g.is_locked_out());
    assert!(g.last_receipt().is_none());
    assert!(g.rollback_history().is_empty());
    assert!(g.cohort_scores().is_empty());
}

#[test]
fn gate_evaluate_approve() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    let d = g.evaluate("r-001", &parity, &cold, 100_000_000);
    assert_eq!(d, GateDecision::Approved);
    assert_eq!(g.approved_count(), 1);
    assert_eq!(g.evaluation_count(), 1);
}

#[test]
fn gate_evaluate_deny_parity_mismatch() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = partial_parity_evidence(200, 10);
    let cold = good_cold_start();
    let d = g.evaluate("r-002", &parity, &cold, 100_000_000);
    assert_eq!(d, GateDecision::Denied);
    let receipt = g.last_receipt().unwrap();
    assert!(receipt.blocking_reasons.iter().any(|r| matches!(r, BlockingReason::ParityMismatch { .. })));
}

#[test]
fn gate_evaluate_deny_cold_start_regression() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = regressing_cold_start();
    let d = g.evaluate("r-003", &parity, &cold, 100_000_000);
    assert_eq!(d, GateDecision::Denied);
}

#[test]
fn gate_evaluate_deny_insufficient_fail_closed() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(10);
    let cold = good_cold_start();
    let d = g.evaluate("r-004", &parity, &cold, 100_000_000);
    assert_eq!(d, GateDecision::Denied);
}

#[test]
fn gate_evaluate_insufficient_fail_open() {
    let config = GateConfig::default().fail_open();
    let mut g = ModuleIndexParityGate::new(config, epoch());
    let parity = full_parity_evidence(200);
    let cold = insufficient_cold_start();
    let d = g.evaluate("r-005", &parity, &cold, 100_000_000);
    assert_eq!(d, GateDecision::Inconclusive);
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

#[test]
fn rollback_increments_counter() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 100,
        },
        1_000_000_000,
    );
    assert_eq!(g.rollback_history().len(), 1);
}

#[test]
fn rollback_lockout_after_max() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        g.rollback(
            &format!("rb-{i}"),
            BlockingReason::ParityMismatch {
                mismatch_count: 1,
                total_tested: 100,
            },
            (i as u64 + 1) * 1_000_000_000,
        );
    }
    assert!(g.is_locked_out());
}

#[test]
fn rollback_lockout_blocks_evaluation() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        g.rollback(
            &format!("rb-{i}"),
            BlockingReason::ParityMismatch {
                mismatch_count: 1,
                total_tested: 100,
            },
            (i as u64 + 1) * 1_000_000_000,
        );
    }
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    let ts = (MAX_CONSECUTIVE_ROLLBACKS as u64 + 100) * 1_000_000_000;
    let d = g.evaluate("r-lockout", &parity, &cold, ts);
    assert_eq!(d, GateDecision::Denied);
}

#[test]
fn cooldown_active() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        BlockingReason::ParityMismatch {
            mismatch_count: 1,
            total_tested: 100,
        },
        1_000_000_000,
    );
    assert!(g.is_cooldown_active(1_000_000_001));
    assert!(!g.is_cooldown_active(1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1));
}

#[test]
fn reset_rollback_counter() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        BlockingReason::ParityMismatch {
            mismatch_count: 1,
            total_tested: 100,
        },
        1_000_000_000,
    );
    g.reset_rollback_counter();
    assert!(!g.is_locked_out());
}

// ---------------------------------------------------------------------------
// Pass rate
// ---------------------------------------------------------------------------

#[test]
fn pass_rate_empty() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    assert_eq!(g.pass_rate_millionths(), 0);
}

#[test]
fn pass_rate_all_approved() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    g.evaluate("r-001", &parity, &cold, 100_000_000);
    g.evaluate("r-002", &parity, &cold, 200_000_000);
    assert_eq!(g.pass_rate_millionths(), MILLIONTHS);
}

#[test]
fn pass_rate_half() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let good_parity = full_parity_evidence(200);
    let bad_parity = partial_parity_evidence(200, 10);
    let cold = good_cold_start();
    g.evaluate("r-001", &good_parity, &cold, 100_000_000);
    g.evaluate("r-002", &bad_parity, &cold, 200_000_000);
    assert_eq!(g.pass_rate_millionths(), 500_000);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

#[test]
fn summary_after_evaluation() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    g.evaluate("r-001", &parity, &cold, 100_000_000);
    let s = g.summary();
    assert_eq!(s.total_evaluations, 1);
    assert_eq!(s.approved_count, 1);
    assert!(!s.is_locked_out);
}

// ---------------------------------------------------------------------------
// Cohort scores
// ---------------------------------------------------------------------------

#[test]
fn cohort_scores_updated() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    g.evaluate("r-001", &parity, &cold, 100_000_000);
    assert_eq!(g.cohort_scores().get("test-cohort"), Some(&MILLIONTHS));
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[test]
fn receipt_approved_no_blocking_reasons() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    g.evaluate("r-001", &parity, &cold, 100_000_000);
    let receipt = g.last_receipt().unwrap();
    assert!(receipt.blocking_reasons.is_empty());
    assert_eq!(receipt.decision, GateDecision::Approved);
}

#[test]
fn receipt_content_hash_deterministic() {
    let mut g1 = ModuleIndexParityGate::with_defaults(epoch());
    let mut g2 = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    g1.evaluate("r-001", &parity, &cold, 100_000_000);
    g2.evaluate("r-001", &parity, &cold, 100_000_000);
    assert_eq!(
        g1.last_receipt().unwrap().content_hash,
        g2.last_receipt().unwrap().content_hash,
    );
}

#[test]
fn receipt_affected_packages() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = partial_parity_evidence(200, 5);
    let cold = good_cold_start();
    g.evaluate("r-003", &parity, &cold, 100_000_000);
    let receipt = g.last_receipt().unwrap();
    assert_eq!(receipt.affected_packages.len(), 5);
}

// ---------------------------------------------------------------------------
// Batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn batch_all_approved() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let cohorts: Vec<_> = (0..3)
        .map(|i| (format!("cohort-{i}"), full_parity_evidence(200), good_cold_start()))
        .collect();
    let result = evaluate_batch(&mut g, &cohorts, 100_000_000);
    assert!(result.all_approved);
    assert_eq!(result.receipts.len(), 3);
}

#[test]
fn batch_partial_denial() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let cohorts = vec![
        ("cohort-ok".to_string(), full_parity_evidence(200), good_cold_start()),
        ("cohort-bad".to_string(), partial_parity_evidence(200, 10), good_cold_start()),
    ];
    let result = evaluate_batch(&mut g, &cohorts, 100_000_000);
    assert!(!result.all_approved);
    assert_eq!(result.summary.approved_count, 1);
    assert_eq!(result.summary.denied_count, 1);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn manifest_initial_state() {
    let m = module_index_parity_gate_manifest();
    assert_eq!(m.total_evaluations, 0);
    assert!(!m.is_locked_out);
    assert_eq!(m.pass_rate_millionths, 0);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn gate_serde_roundtrip() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    g.evaluate("r-001", &parity, &cold, 100_000_000);
    let json = serde_json::to_string(&g).unwrap();
    let back: ModuleIndexParityGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 1);
}

#[test]
fn rollback_record_serde_roundtrip() {
    let r = RollbackRecord::new(
        "rb-001",
        epoch(),
        BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 100,
        },
        1_000_000_000,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r.record_id, back.record_id);
}

#[test]
fn rollback_record_hash_nontrivial() {
    let r = RollbackRecord::new(
        "rb-001",
        epoch(),
        BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 100,
        },
        1_000_000_000,
    );
    assert_ne!(r.content_hash, ContentHash::compute(b""));
}

#[test]
fn gate_summary_serde_roundtrip() {
    let s = GateSummary {
        total_evaluations: 10,
        approved_count: 7,
        denied_count: 3,
        rollback_count: 1,
        is_locked_out: false,
        pass_rate_millionths: 700_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}
