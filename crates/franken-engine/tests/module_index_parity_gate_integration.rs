//! Integration tests for module_index_parity_gate (RGC-406C).
//!
//! Bead: bd-1lsy.5.8.3

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

use frankenengine_engine::module_index_parity_gate::{
    self, BEAD_ID, BlockingReason, COMPONENT, ColdStartEvidence, ColdStartVerdict,
    DEFAULT_COLD_START_BUDGET_MILLIONTHS, DEFAULT_MIN_SPECIFIER_COUNT,
    DEFAULT_PARITY_THRESHOLD_MILLIONTHS, DEFAULT_ROLLBACK_COOLDOWN_NS, GateConfig, GateDecision,
    MAX_CONSECUTIVE_ROLLBACKS, MILLIONTHS, ModuleIndexParityGate, POLICY_ID, ParityEvidence,
    ParityVerdict, RollbackRecord, SCHEMA_VERSION, SpecifierResult,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
fn test_schema_version() {
    assert!(SCHEMA_VERSION.contains("module-index-parity-gate"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert_eq!(COMPONENT, "module_index_parity_gate");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-406C");
}

#[test]
fn test_millionths_value() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn test_default_parity_threshold() {
    assert_eq!(DEFAULT_PARITY_THRESHOLD_MILLIONTHS, 1_000_000);
}

#[test]
fn test_default_cold_start_budget() {
    assert_eq!(DEFAULT_COLD_START_BUDGET_MILLIONTHS, 50_000);
}

#[test]
fn test_default_min_specifier_count() {
    assert_eq!(DEFAULT_MIN_SPECIFIER_COUNT, 100);
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_parity_verdict_shippable() {
    assert!(ParityVerdict::FullParity.is_shippable());
    assert!(!ParityVerdict::PartialParity.is_shippable());
    assert!(!ParityVerdict::NoParity.is_shippable());
    assert!(!ParityVerdict::InsufficientData.is_shippable());
}

#[test]
fn test_parity_verdict_as_str() {
    assert_eq!(ParityVerdict::FullParity.as_str(), "full_parity");
    assert_eq!(ParityVerdict::PartialParity.as_str(), "partial_parity");
    assert_eq!(ParityVerdict::NoParity.as_str(), "no_parity");
    assert_eq!(
        ParityVerdict::InsufficientData.as_str(),
        "insufficient_data"
    );
}

#[test]
fn test_parity_verdict_display() {
    assert_eq!(format!("{}", ParityVerdict::FullParity), "full_parity");
}

#[test]
fn test_parity_verdict_serde_roundtrip() {
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
fn test_cold_start_verdict_acceptable() {
    assert!(ColdStartVerdict::WithinBudget.is_acceptable());
    assert!(!ColdStartVerdict::Regression.is_acceptable());
    assert!(!ColdStartVerdict::InsufficientSamples.is_acceptable());
}

#[test]
fn test_cold_start_verdict_display() {
    assert_eq!(
        format!("{}", ColdStartVerdict::WithinBudget),
        "within_budget"
    );
    assert_eq!(format!("{}", ColdStartVerdict::Regression), "regression");
}

#[test]
fn test_cold_start_verdict_serde() {
    let v = ColdStartVerdict::Regression;
    let json = serde_json::to_string(&v).unwrap();
    let back: ColdStartVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

#[test]
fn test_gate_decision_approved() {
    assert!(GateDecision::Approved.is_approved());
    assert!(!GateDecision::Denied.is_approved());
    assert!(!GateDecision::RolledBack.is_approved());
    assert!(!GateDecision::Inconclusive.is_approved());
}

#[test]
fn test_gate_decision_as_str() {
    assert_eq!(GateDecision::Approved.as_str(), "approved");
    assert_eq!(GateDecision::Denied.as_str(), "denied");
    assert_eq!(GateDecision::RolledBack.as_str(), "rolled_back");
    assert_eq!(GateDecision::Inconclusive.as_str(), "inconclusive");
}

#[test]
fn test_gate_decision_display() {
    assert_eq!(format!("{}", GateDecision::Denied), "denied");
}

// ---------------------------------------------------------------------------
// BlockingReason
// ---------------------------------------------------------------------------

#[test]
fn test_blocking_reason_parity_display() {
    let r = BlockingReason::ParityMismatch {
        mismatch_count: 5,
        total_tested: 200,
    };
    let s = format!("{r}");
    assert!(s.contains("5/200"));
}

#[test]
fn test_blocking_reason_cold_start_display() {
    let r = BlockingReason::ColdStartRegression {
        regression_millionths: 100_000,
        budget_millionths: 50_000,
    };
    let s = format!("{r}");
    assert!(s.contains("100000>50000"));
}

#[test]
fn test_blocking_reason_coverage_display() {
    let r = BlockingReason::InsufficientCoverage {
        sampled: 10,
        minimum_required: 100,
    };
    let s = format!("{r}");
    assert!(s.contains("10<100"));
}

#[test]
fn test_blocking_reason_lockout_display() {
    let r = BlockingReason::RollbackLockout {
        consecutive_rollbacks: 3,
    };
    assert!(format!("{r}").contains("3"));
}

#[test]
fn test_blocking_reason_cooldown_display() {
    let r = BlockingReason::CooldownActive {
        remaining_ns: 5_000_000,
    };
    assert!(format!("{r}").contains("5000000"));
}

#[test]
fn test_blocking_reason_serde_roundtrip() {
    let reasons = vec![
        BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 200,
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
        BlockingReason::CooldownActive { remaining_ns: 1000 },
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
fn test_specifier_result_matching() {
    let r = matching_result("react");
    assert!(r.matches);
    assert!(r.baseline_path.is_some());
    assert!(r.index_path.is_some());
}

#[test]
fn test_specifier_result_mismatching() {
    let r = mismatching_result("react");
    assert!(!r.matches);
}

#[test]
fn test_specifier_result_hash_deterministic() {
    let a = matching_result("react");
    let b = matching_result("react");
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_specifier_result_different_specs_different_hash() {
    let a = matching_result("react");
    let b = matching_result("lodash");
    assert_ne!(a.content_hash(), b.content_hash());
}

// ---------------------------------------------------------------------------
// ParityEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_parity_evidence_full_match() {
    let ev = full_parity_evidence(200);
    assert_eq!(ev.match_count, 200);
    assert_eq!(ev.mismatch_count, 0);
    assert_eq!(ev.parity_ratio_millionths, MILLIONTHS);
    assert_eq!(ev.total_tested, 200);
}

#[test]
fn test_parity_evidence_partial_match() {
    let ev = partial_parity_evidence(200, 20);
    assert_eq!(ev.match_count, 180);
    assert_eq!(ev.mismatch_count, 20);
    assert!(ev.parity_ratio_millionths > 0);
    assert!(ev.parity_ratio_millionths < MILLIONTHS);
}

#[test]
fn test_parity_evidence_all_mismatch() {
    let results: Vec<_> = (0..100)
        .map(|i| mismatching_result(&format!("pkg-{i:04}")))
        .collect();
    let ev = ParityEvidence::from_results("ev", "cohort", results);
    assert_eq!(ev.match_count, 0);
    assert_eq!(ev.parity_ratio_millionths, 0);
}

#[test]
fn test_parity_evidence_empty() {
    let ev = ParityEvidence::from_results("ev", "empty", vec![]);
    assert_eq!(ev.total_tested, 0);
    assert_eq!(ev.parity_ratio_millionths, 0);
}

#[test]
fn test_parity_evidence_seal_deterministic() {
    let a = full_parity_evidence(200);
    let b = full_parity_evidence(200);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_parity_evidence_serde_roundtrip() {
    let ev = full_parity_evidence(50);
    let json = serde_json::to_string(&ev).unwrap();
    let back: ParityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// ColdStartEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_cold_start_speedup() {
    let ev = ColdStartEvidence::new("ev", 1_000_000, 800_000, 100);
    assert!(ev.is_speedup);
    assert_eq!(ev.regression_millionths, 0);
}

#[test]
fn test_cold_start_regression_value() {
    let ev = ColdStartEvidence::new("ev", 1_000_000, 1_200_000, 100);
    assert!(!ev.is_speedup);
    assert_eq!(ev.regression_millionths, 200_000);
}

#[test]
fn test_cold_start_equal() {
    let ev = ColdStartEvidence::new("ev", 1_000_000, 1_000_000, 100);
    assert!(ev.is_speedup);
    assert_eq!(ev.regression_millionths, 0);
}

#[test]
fn test_cold_start_zero_baseline() {
    let ev = ColdStartEvidence::new("ev", 0, 100, 10);
    // Should not panic on zero division
    assert_eq!(ev.regression_millionths, 0);
}

#[test]
fn test_cold_start_seal_deterministic() {
    let a = good_cold_start();
    let b = good_cold_start();
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_cold_start_serde() {
    let ev = good_cold_start();
    let json = serde_json::to_string(&ev).unwrap();
    let back: ColdStartEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_record_creation() {
    let r = RollbackRecord::new(
        "rb-001",
        epoch(),
        BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 100,
        },
        1_000_000_000,
    );
    assert_eq!(r.record_id, "rb-001");
    assert_eq!(r.epoch.as_u64(), 1);
    assert_eq!(r.timestamp_ns, 1_000_000_000);
}

#[test]
fn test_rollback_record_serde() {
    let r = RollbackRecord::new(
        "rb-001",
        epoch(),
        BlockingReason::ColdStartRegression {
            regression_millionths: 100_000,
            budget_millionths: 50_000,
        },
        2_000_000_000,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r.record_id, back.record_id);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_config_default() {
    let c = GateConfig::default();
    assert_eq!(c.parity_threshold_millionths, MILLIONTHS);
    assert_eq!(c.cold_start_budget_millionths, 50_000);
    assert_eq!(c.min_specifier_count, 100);
    assert_eq!(c.max_consecutive_rollbacks, 3);
    assert!(c.fail_closed);
}

#[test]
fn test_config_with_parity_threshold() {
    let c = GateConfig::default().with_parity_threshold(900_000);
    assert_eq!(c.parity_threshold_millionths, 900_000);
}

#[test]
fn test_config_with_cold_start_budget() {
    let c = GateConfig::default().with_cold_start_budget(100_000);
    assert_eq!(c.cold_start_budget_millionths, 100_000);
}

#[test]
fn test_config_fail_open() {
    let c = GateConfig::default().fail_open();
    assert!(!c.fail_closed);
}

#[test]
fn test_config_serde_roundtrip() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// ModuleIndexParityGate — construction
// ---------------------------------------------------------------------------

#[test]
fn test_gate_new_default() {
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
fn test_gate_custom_epoch() {
    let g = ModuleIndexParityGate::with_defaults(SecurityEpoch::from_raw(99));
    assert_eq!(g.epoch().as_u64(), 99);
}

#[test]
fn test_gate_custom_config() {
    let config = GateConfig::default().with_parity_threshold(900_000);
    let g = ModuleIndexParityGate::new(config, epoch());
    assert_eq!(g.config().parity_threshold_millionths, 900_000);
}

// ---------------------------------------------------------------------------
// ModuleIndexParityGate — evaluate_parity
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_parity_full() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    let ev = full_parity_evidence(200);
    assert_eq!(g.evaluate_parity(&ev), ParityVerdict::FullParity);
}

#[test]
fn test_evaluate_parity_partial() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    let ev = partial_parity_evidence(200, 10);
    assert_eq!(g.evaluate_parity(&ev), ParityVerdict::PartialParity);
}

#[test]
fn test_evaluate_parity_none() {
    let results: Vec<_> = (0..200)
        .map(|i| mismatching_result(&format!("pkg-{i:04}")))
        .collect();
    let ev = ParityEvidence::from_results("ev", "cohort", results);
    let g = ModuleIndexParityGate::with_defaults(epoch());
    assert_eq!(g.evaluate_parity(&ev), ParityVerdict::NoParity);
}

#[test]
fn test_evaluate_parity_insufficient() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    let ev = full_parity_evidence(10);
    assert_eq!(g.evaluate_parity(&ev), ParityVerdict::InsufficientData);
}

#[test]
fn test_evaluate_parity_custom_threshold() {
    let config = GateConfig::default().with_parity_threshold(900_000);
    let g = ModuleIndexParityGate::new(config, epoch());
    // 95% parity is above 90% threshold
    let ev = partial_parity_evidence(200, 10);
    assert_eq!(g.evaluate_parity(&ev), ParityVerdict::FullParity);
}

// ---------------------------------------------------------------------------
// ModuleIndexParityGate — evaluate_cold_start
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_cold_start_within_budget() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    assert_eq!(
        g.evaluate_cold_start(&good_cold_start()),
        ColdStartVerdict::WithinBudget,
    );
}

#[test]
fn test_evaluate_cold_start_regression() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    assert_eq!(
        g.evaluate_cold_start(&regressing_cold_start()),
        ColdStartVerdict::Regression,
    );
}

#[test]
fn test_evaluate_cold_start_insufficient() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    assert_eq!(
        g.evaluate_cold_start(&insufficient_cold_start()),
        ColdStartVerdict::InsufficientSamples,
    );
}

// ---------------------------------------------------------------------------
// ModuleIndexParityGate — full evaluate
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_approve() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let d = g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    assert_eq!(d, GateDecision::Approved);
    assert_eq!(g.approved_count(), 1);
    assert_eq!(g.evaluation_count(), 1);
}

#[test]
fn test_evaluate_deny_parity() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let d = g.evaluate(
        "r-001",
        &partial_parity_evidence(200, 10),
        &good_cold_start(),
        100_000_000,
    );
    assert_eq!(d, GateDecision::Denied);
    assert_eq!(g.denied_count(), 1);
}

#[test]
fn test_evaluate_deny_cold_start() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let d = g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &regressing_cold_start(),
        100_000_000,
    );
    assert_eq!(d, GateDecision::Denied);
}

#[test]
fn test_evaluate_deny_both_bad() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let d = g.evaluate(
        "r-001",
        &partial_parity_evidence(200, 10),
        &regressing_cold_start(),
        100_000_000,
    );
    assert_eq!(d, GateDecision::Denied);
    let receipt = g.last_receipt().unwrap();
    assert!(receipt.blocking_reasons.len() >= 2);
}

#[test]
fn test_evaluate_deny_insufficient_fail_closed() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let d = g.evaluate(
        "r-001",
        &full_parity_evidence(10),
        &good_cold_start(),
        100_000_000,
    );
    assert_eq!(d, GateDecision::Denied);
}

#[test]
fn test_evaluate_fail_open_insufficient() {
    let config = GateConfig::default().fail_open();
    let mut g = ModuleIndexParityGate::new(config, epoch());
    let d = g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &insufficient_cold_start(),
        100_000_000,
    );
    assert_eq!(d, GateDecision::Approved);
}

#[test]
fn test_evaluate_multiple_increments_counters() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(200);
    let cold = good_cold_start();
    for i in 0..5 {
        g.evaluate(
            &format!("r-{i:03}"),
            &parity,
            &cold,
            (i as u64 + 1) * 100_000_000,
        );
    }
    assert_eq!(g.evaluation_count(), 5);
    assert_eq!(g.approved_count(), 5);
}

// ---------------------------------------------------------------------------
// Rollback governance
// ---------------------------------------------------------------------------

#[test]
fn test_rollback() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let record = g.rollback(
        "rb-001",
        BlockingReason::ParityMismatch {
            mismatch_count: 5,
            total_tested: 100,
        },
        1_000_000_000,
    );
    assert_eq!(record.record_id, "rb-001");
    assert_eq!(g.rollback_history().len(), 1);
}

#[test]
fn test_rollback_lockout() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        g.rollback(
            &format!("rb-{i:03}"),
            BlockingReason::ParityMismatch {
                mismatch_count: 1,
                total_tested: 100,
            },
            (i as u64 + 1) * 1_000_000_000,
        );
    }
    assert!(g.is_locked_out());

    // Even good evidence should be denied
    let d = g.evaluate(
        "r-locked",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000_000,
    );
    assert_eq!(d, GateDecision::Denied);
}

#[test]
fn test_cooldown_blocks_evaluation() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        BlockingReason::ColdStartRegression {
            regression_millionths: 200_000,
            budget_millionths: 50_000,
        },
        1_000_000_000,
    );
    // Evaluate during cooldown
    let d = g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        1_000_000_001, // within cooldown
    );
    assert_eq!(d, GateDecision::Denied);
    let receipt = g.last_receipt().unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| { matches!(r, BlockingReason::CooldownActive { .. }) })
    );
}

#[test]
fn test_cooldown_expires() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.rollback(
        "rb-001",
        BlockingReason::ParityMismatch {
            mismatch_count: 1,
            total_tested: 100,
        },
        1_000_000_000,
    );
    // After cooldown expires
    let ts = 1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1;
    assert!(!g.is_cooldown_active(ts));
}

#[test]
fn test_reset_rollback_counter() {
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
// Pass rate and summary
// ---------------------------------------------------------------------------

#[test]
fn test_pass_rate_empty() {
    let g = ModuleIndexParityGate::with_defaults(epoch());
    assert_eq!(g.pass_rate_millionths(), 0);
}

#[test]
fn test_pass_rate_all_pass() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    for i in 0..3 {
        g.evaluate(
            &format!("r-{i:03}"),
            &full_parity_evidence(200),
            &good_cold_start(),
            (i as u64 + 1) * 100_000_000,
        );
    }
    assert_eq!(g.pass_rate_millionths(), MILLIONTHS);
}

#[test]
fn test_pass_rate_half() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    g.evaluate(
        "r-002",
        &partial_parity_evidence(200, 10),
        &good_cold_start(),
        200_000_000,
    );
    assert_eq!(g.pass_rate_millionths(), 500_000);
}

#[test]
fn test_summary() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    let s = g.summary();
    assert_eq!(s.total_evaluations, 1);
    assert_eq!(s.approved_count, 1);
    assert_eq!(s.denied_count, 0);
    assert_eq!(s.rollback_count, 0);
    assert!(!s.is_locked_out);
}

// ---------------------------------------------------------------------------
// Cohort scores
// ---------------------------------------------------------------------------

#[test]
fn test_cohort_scores_tracked() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    assert_eq!(g.cohort_scores().get("test-cohort"), Some(&MILLIONTHS));
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_present() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    assert!(g.last_receipt().is_none());
    g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    assert!(g.last_receipt().is_some());
}

#[test]
fn test_receipt_approved_clean() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    let receipt = g.last_receipt().unwrap();
    assert_eq!(receipt.decision, GateDecision::Approved);
    assert!(receipt.blocking_reasons.is_empty());
    assert_eq!(receipt.parity_verdict, ParityVerdict::FullParity);
    assert_eq!(receipt.cold_start_verdict, ColdStartVerdict::WithinBudget);
}

#[test]
fn test_receipt_denied_with_reasons() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.evaluate(
        "r-001",
        &partial_parity_evidence(200, 10),
        &good_cold_start(),
        100_000_000,
    );
    let receipt = g.last_receipt().unwrap();
    assert_eq!(receipt.decision, GateDecision::Denied);
    assert!(!receipt.blocking_reasons.is_empty());
}

#[test]
fn test_receipt_affected_packages() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.evaluate(
        "r-001",
        &partial_parity_evidence(200, 5),
        &good_cold_start(),
        100_000_000,
    );
    let receipt = g.last_receipt().unwrap();
    assert_eq!(receipt.affected_packages.len(), 5);
}

#[test]
fn test_receipt_hash_deterministic() {
    let mut g1 = ModuleIndexParityGate::with_defaults(epoch());
    let mut g2 = ModuleIndexParityGate::with_defaults(epoch());
    g1.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    g2.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    assert_eq!(
        g1.last_receipt().unwrap().content_hash,
        g2.last_receipt().unwrap().content_hash,
    );
}

// ---------------------------------------------------------------------------
// Batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_batch_all_approved() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let cohorts: Vec<_> = (0..3)
        .map(|i| {
            (
                format!("cohort-{i}"),
                full_parity_evidence(200),
                good_cold_start(),
            )
        })
        .collect();
    let result = module_index_parity_gate::evaluate_batch(&mut g, &cohorts, 100_000_000);
    assert!(result.all_approved);
    assert_eq!(result.receipts.len(), 3);
}

#[test]
fn test_batch_partial_denial() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let cohorts = vec![
        (
            "c-ok".to_string(),
            full_parity_evidence(200),
            good_cold_start(),
        ),
        (
            "c-bad".to_string(),
            partial_parity_evidence(200, 10),
            good_cold_start(),
        ),
    ];
    let result = module_index_parity_gate::evaluate_batch(&mut g, &cohorts, 100_000_000);
    assert!(!result.all_approved);
    assert_eq!(result.summary.approved_count, 1);
    assert_eq!(result.summary.denied_count, 1);
}

#[test]
fn test_batch_empty() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let result = module_index_parity_gate::evaluate_batch(&mut g, &[], 100_000_000);
    assert!(result.all_approved);
    assert!(result.receipts.is_empty());
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest() {
    let m = module_index_parity_gate::module_index_parity_gate_manifest();
    assert_eq!(m.total_evaluations, 0);
    assert!(!m.is_locked_out);
}

// ---------------------------------------------------------------------------
// Gate serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_gate_serde_roundtrip() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    g.evaluate(
        "r-001",
        &full_parity_evidence(200),
        &good_cold_start(),
        100_000_000,
    );
    let json = serde_json::to_string(&g).unwrap();
    let back: ModuleIndexParityGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 1);
    assert_eq!(back.approved_count(), 1);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_large_cohort() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    let parity = full_parity_evidence(1000);
    let cold = good_cold_start();
    let d = g.evaluate("r-big", &parity, &cold, 100_000_000);
    assert_eq!(d, GateDecision::Approved);
}

#[test]
fn test_repeated_evaluations_same_cohort() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    for i in 0..10 {
        g.evaluate(
            &format!("r-{i:03}"),
            &full_parity_evidence(200),
            &good_cold_start(),
            (i as u64 + 1) * 100_000_000,
        );
    }
    assert_eq!(g.evaluation_count(), 10);
    assert_eq!(g.approved_count(), 10);
    // Cohort score should be latest
    assert_eq!(g.cohort_scores().get("test-cohort"), Some(&MILLIONTHS));
}

#[test]
fn test_approval_resets_consecutive_rollbacks() {
    let mut g = ModuleIndexParityGate::with_defaults(epoch());
    // One rollback
    g.rollback(
        "rb-001",
        BlockingReason::ParityMismatch {
            mismatch_count: 1,
            total_tested: 100,
        },
        1_000_000_000,
    );
    // Approval should reset counter
    let ts = 1_000_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS + 1;
    g.evaluate("r-001", &full_parity_evidence(200), &good_cold_start(), ts);
    assert!(!g.is_locked_out());
}
