//! Integration tests for the `signature_drift_gate` module.
//!
//! Exercises the full public API from outside the crate: snapshot construction,
//! drift computation, transition budget tracking, gate evaluation (pass /
//! downgrade / block / abstain), batch evaluation, claim scope ledger, evidence
//! corpus, serde round-trips, and boundary / edge-case coverage.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::RegimeLabel;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_drift_gate::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn normal() -> RegimeLabel {
    RegimeLabel::Classified(Regime::Normal)
}

fn elevated() -> RegimeLabel {
    RegimeLabel::Classified(Regime::Elevated)
}

fn features(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn snap(
    id: &str,
    regime: RegimeLabel,
    feats: &[(&str, i64)],
    obs: u64,
    ep: SecurityEpoch,
) -> SignatureSnapshot {
    SignatureSnapshot::new(id.to_string(), regime, features(feats), obs, ep)
}

fn default_cfg() -> DriftGateConfig {
    DriftGateConfig::default()
}

fn fresh_budget(ep: SecurityEpoch) -> TransitionBudgetTracker {
    TransitionBudgetTracker::new(DEFAULT_MAX_TRANSITIONS, ep)
}

fn make_scope_record(claim_id: &str, ep: SecurityEpoch) -> ClaimScopeRecord {
    ClaimScopeRecord {
        claim_id: claim_id.to_string(),
        valid_regime: normal(),
        baseline_hash: ContentHash::compute(b"baseline"),
        max_passing_drift_millionths: 0,
        active: true,
        deactivation_reason: None,
        last_validated_epoch: ep,
    }
}

// ===========================================================================
// Section 1: Constants
// ===========================================================================

#[test]
fn test_schema_version_is_v1() {
    assert_eq!(
        DRIFT_GATE_SCHEMA_VERSION,
        "franken-engine.signature-drift-gate.v1"
    );
}

#[test]
fn test_default_constants_are_positive() {
    assert!(DEFAULT_MAX_DRIFT_MILLIONTHS > 0);
    assert!(DEFAULT_MAX_TRANSITIONS > 0);
    assert!(DEFAULT_MAX_STALENESS_EPOCHS > 0);
    assert!(MIN_OBSERVATIONS_FOR_DRIFT > 0);
}

// ===========================================================================
// Section 2: SignatureSnapshot
// ===========================================================================

#[test]
fn test_snapshot_new_sets_fields() {
    let s = snap(
        "snap-1",
        normal(),
        &[("cpu", 500_000), ("mem", 200_000)],
        50,
        epoch(10),
    );
    assert_eq!(s.signature_id, "snap-1");
    assert_eq!(s.regime, normal());
    assert_eq!(s.observation_count, 50);
    assert_eq!(s.epoch, epoch(10));
    assert_eq!(s.dimension(), 2);
}

#[test]
fn test_snapshot_trustworthy_at_threshold() {
    let s = snap(
        "t",
        normal(),
        &[("a", 1)],
        MIN_OBSERVATIONS_FOR_DRIFT,
        epoch(1),
    );
    assert!(s.is_trustworthy());
}

#[test]
fn test_snapshot_untrustworthy_below_threshold() {
    let s = snap(
        "u",
        normal(),
        &[("a", 1)],
        MIN_OBSERVATIONS_FOR_DRIFT - 1,
        epoch(1),
    );
    assert!(!s.is_trustworthy());
}

#[test]
fn test_snapshot_dimension_empty() {
    let s = snap("e", normal(), &[], 100, epoch(1));
    assert_eq!(s.dimension(), 0);
}

#[test]
fn test_snapshot_content_hash_deterministic() {
    let a = snap("id", normal(), &[("x", 42)], 10, epoch(1));
    let b = snap("id", normal(), &[("x", 42)], 10, epoch(1));
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn test_snapshot_content_hash_differs_on_id() {
    let a = snap("id-a", normal(), &[("x", 42)], 10, epoch(1));
    let b = snap("id-b", normal(), &[("x", 42)], 10, epoch(1));
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn test_snapshot_content_hash_differs_on_features() {
    let a = snap("s", normal(), &[("x", 100)], 10, epoch(1));
    let b = snap("s", normal(), &[("x", 200)], 10, epoch(1));
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn test_snapshot_serde_roundtrip() {
    let s = snap(
        "serde",
        normal(),
        &[("cpu", 750_000), ("io", 250_000)],
        42,
        epoch(7),
    );
    let json = serde_json::to_string(&s).unwrap();
    let back: SignatureSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// Section 3: DriftMeasurement via compute_drift
// ===========================================================================

#[test]
fn test_drift_identical_snapshots_zero() {
    let s = snap(
        "s",
        normal(),
        &[("a", 500_000), ("b", 300_000)],
        100,
        epoch(1),
    );
    let d = compute_drift(&s, &s);
    assert_eq!(d.l1_drift_millionths, 0);
    assert_eq!(d.linf_drift_millionths, 0);
    assert_eq!(d.shared_dimensions, 2);
    assert!(!d.regime_changed);
    assert!(d.missing_features.is_empty());
    assert!(d.new_features.is_empty());
}

#[test]
fn test_drift_l1_and_linf_computation() {
    let bl = snap(
        "bl",
        normal(),
        &[("a", 100_000), ("b", 200_000)],
        100,
        epoch(1),
    );
    let cur = snap(
        "cur",
        normal(),
        &[("a", 180_000), ("b", 230_000)],
        100,
        epoch(1),
    );
    let d = compute_drift(&bl, &cur);
    // a drift = 80_000, b drift = 30_000
    assert_eq!(d.l1_drift_millionths, 110_000);
    assert_eq!(d.linf_drift_millionths, 80_000);
    assert_eq!(d.shared_dimensions, 2);
}

#[test]
fn test_drift_missing_and_new_features() {
    let bl = snap(
        "bl",
        normal(),
        &[("old", 100_000), ("shared", 500_000)],
        100,
        epoch(1),
    );
    let cur = snap(
        "cur",
        normal(),
        &[("shared", 510_000), ("new", 200_000)],
        100,
        epoch(1),
    );
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.shared_dimensions, 1);
    assert!(d.missing_features.contains("old"));
    assert!(d.new_features.contains("new"));
    assert_eq!(d.l1_drift_millionths, 10_000);
}

#[test]
fn test_drift_no_shared_features() {
    let bl = snap("bl", normal(), &[("a", 100_000)], 100, epoch(1));
    let cur = snap("cur", normal(), &[("b", 200_000)], 100, epoch(1));
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.shared_dimensions, 0);
    assert_eq!(d.l1_drift_millionths, 0);
    assert_eq!(d.linf_drift_millionths, 0);
}

#[test]
fn test_drift_regime_changed_detected() {
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, epoch(1));
    let cur = snap("cur", elevated(), &[("a", 500_000)], 100, epoch(1));
    let d = compute_drift(&bl, &cur);
    assert!(d.regime_changed);
    assert_eq!(d.l1_drift_millionths, 0);
}

#[test]
fn test_drift_serde_roundtrip() {
    let bl = snap("bl", normal(), &[("x", 100_000)], 100, epoch(1));
    let cur = snap("cur", normal(), &[("x", 300_000)], 100, epoch(1));
    let d = compute_drift(&bl, &cur);
    let json = serde_json::to_string(&d).unwrap();
    let back: DriftMeasurement = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ===========================================================================
// Section 4: TransitionBudgetTracker
// ===========================================================================

#[test]
fn test_budget_new_is_within_budget() {
    let b = TransitionBudgetTracker::new(5, epoch(1));
    assert!(b.is_within_budget());
    assert_eq!(b.remaining(), 5);
    assert_eq!(b.transitions_consumed, 0);
    assert_eq!(b.utilization_millionths(), 0);
}

#[test]
fn test_budget_record_transition_decrement() {
    let mut b = TransitionBudgetTracker::new(3, epoch(1));
    let ok = b.record_transition(normal(), elevated(), 10_000, epoch(2));
    assert!(ok);
    assert_eq!(b.remaining(), 2);
    assert_eq!(b.history.len(), 1);
    assert_eq!(b.history[0].sequence, 1);
}

#[test]
fn test_budget_exhaustion_returns_false() {
    let mut b = TransitionBudgetTracker::new(1, epoch(1));
    assert!(b.record_transition(normal(), elevated(), 0, epoch(2)));
    // Now consumed == 1, max == 1 -> still within
    // Next one exceeds
    assert!(!b.record_transition(elevated(), normal(), 0, epoch(3)));
    assert!(!b.is_within_budget());
}

#[test]
fn test_budget_utilization_half() {
    let mut b = TransitionBudgetTracker::new(4, epoch(1));
    b.record_transition(normal(), normal(), 0, epoch(2));
    b.record_transition(normal(), normal(), 0, epoch(3));
    assert_eq!(b.utilization_millionths(), 500_000); // 2/4 = 50%
}

#[test]
fn test_budget_utilization_full() {
    let mut b = TransitionBudgetTracker::new(2, epoch(1));
    b.record_transition(normal(), normal(), 0, epoch(2));
    b.record_transition(normal(), normal(), 0, epoch(3));
    assert_eq!(b.utilization_millionths(), 1_000_000); // 2/2 = 100%
}

#[test]
fn test_budget_zero_max_utilization() {
    let b = TransitionBudgetTracker::new(0, epoch(1));
    // 0 consumed <= 0 max -> within budget
    assert!(b.is_within_budget());
    // But utilization is 100% (0/0 special case)
    assert_eq!(b.utilization_millionths(), 1_000_000);
}

#[test]
fn test_budget_reset_clears_state() {
    let mut b = TransitionBudgetTracker::new(2, epoch(1));
    b.record_transition(normal(), normal(), 0, epoch(2));
    b.record_transition(normal(), normal(), 0, epoch(3));
    b.record_transition(normal(), normal(), 0, epoch(4));
    assert!(!b.is_within_budget());

    b.reset(epoch(100));
    assert!(b.is_within_budget());
    assert_eq!(b.remaining(), 2);
    assert!(b.history.is_empty());
    assert_eq!(b.reset_epoch, epoch(100));
}

#[test]
fn test_budget_serde_roundtrip() {
    let mut b = TransitionBudgetTracker::new(5, epoch(1));
    b.record_transition(normal(), elevated(), 50_000, epoch(2));
    let json = serde_json::to_string(&b).unwrap();
    let back: TransitionBudgetTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ===========================================================================
// Section 5: DriftGateConfig
// ===========================================================================

#[test]
fn test_config_default_values() {
    let cfg = default_cfg();
    assert_eq!(cfg.max_l1_drift_millionths, DEFAULT_MAX_DRIFT_MILLIONTHS);
    assert_eq!(
        cfg.max_linf_drift_millionths,
        DEFAULT_MAX_DRIFT_MILLIONTHS / 2
    );
    assert_eq!(cfg.max_transitions, DEFAULT_MAX_TRANSITIONS);
    assert_eq!(cfg.max_staleness_epochs, DEFAULT_MAX_STALENESS_EPOCHS);
    assert_eq!(cfg.min_observations, MIN_OBSERVATIONS_FOR_DRIFT);
    assert!(cfg.regime_change_triggers_downgrade);
}

#[test]
fn test_config_serde_roundtrip() {
    let cfg = default_cfg();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: DriftGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// Section 6: DowngradeReason and GateVerdict Display
// ===========================================================================

#[test]
fn test_downgrade_reason_display_all_variants() {
    let cases = [
        (DowngradeReason::ExcessiveL1Drift, "excessive_l1_drift"),
        (DowngradeReason::ExcessiveLinfDrift, "excessive_linf_drift"),
        (
            DowngradeReason::TransitionBudgetExhausted,
            "transition_budget_exhausted",
        ),
        (DowngradeReason::RegimeChanged, "regime_changed"),
        (DowngradeReason::StaleBaseline, "stale_baseline"),
        (
            DowngradeReason::InsufficientBaselineObservations,
            "insufficient_baseline_observations",
        ),
        (
            DowngradeReason::InsufficientCurrentObservations,
            "insufficient_current_observations",
        ),
        (DowngradeReason::NoSharedDimensions, "no_shared_dimensions"),
    ];
    for (reason, expected) in &cases {
        assert_eq!(reason.to_string(), *expected);
    }
}

#[test]
fn test_downgrade_reason_serde_roundtrip() {
    for reason in [
        DowngradeReason::ExcessiveL1Drift,
        DowngradeReason::RegimeChanged,
        DowngradeReason::NoSharedDimensions,
    ] {
        let json = serde_json::to_string(&reason).unwrap();
        let back: DowngradeReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }
}

#[test]
fn test_gate_verdict_display() {
    assert_eq!(GateVerdict::Pass.to_string(), "pass");
    assert_eq!(GateVerdict::Downgrade.to_string(), "downgrade");
    assert_eq!(GateVerdict::Block.to_string(), "block");
    assert_eq!(GateVerdict::Abstain.to_string(), "abstain");
}

#[test]
fn test_gate_verdict_serde_roundtrip() {
    for v in [
        GateVerdict::Pass,
        GateVerdict::Downgrade,
        GateVerdict::Block,
        GateVerdict::Abstain,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// Section 7: evaluate_gate — Pass
// ===========================================================================

#[test]
fn test_gate_pass_low_drift_same_regime() {
    let ep = epoch(50);
    let bl = snap(
        "bl",
        normal(),
        &[("cpu", 500_000), ("mem", 300_000)],
        100,
        ep,
    );
    let cur = snap(
        "cur",
        normal(),
        &[("cpu", 510_000), ("mem", 305_000)],
        100,
        ep,
    );
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-pass", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(decision.is_pass());
    assert!(!decision.is_blocked());
    assert!(!decision.is_abstained());
    assert_eq!(decision.reason_count(), 0);
    assert!(decision.downgrade_reasons.is_empty());
    assert!(decision.decision_id.starts_with("dg-pass-"));
    assert_eq!(decision.schema_version, DRIFT_GATE_SCHEMA_VERSION);
    assert_eq!(decision.claim_id, "claim-pass");
    assert!(decision.drift.is_some());
}

#[test]
fn test_gate_pass_at_exact_l1_threshold() {
    // Configure so drift exactly equals threshold => still passes (> not >=)
    let ep = epoch(50);
    let cfg = DriftGateConfig {
        max_l1_drift_millionths: 100_000,
        max_linf_drift_millionths: 100_000,
        ..default_cfg()
    };
    let bl = snap("bl", normal(), &[("a", 0)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 100_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-boundary", &bl, &cur, &budget, &cfg, ep);
    // drift.l1 == 100_000, threshold == 100_000, condition is > so should pass
    assert!(decision.is_pass());
}

// ===========================================================================
// Section 8: evaluate_gate — Downgrade
// ===========================================================================

#[test]
fn test_gate_downgrade_excessive_l1_drift() {
    let ep = epoch(50);
    let bl = snap(
        "bl",
        normal(),
        &[("cpu", 100_000), ("mem", 100_000)],
        100,
        ep,
    );
    let cur = snap(
        "cur",
        normal(),
        &[("cpu", 500_000), ("mem", 500_000)],
        100,
        ep,
    );
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-drift", &bl, &cur, &budget, &default_cfg(), ep);

    assert_eq!(decision.verdict, GateVerdict::Downgrade);
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::ExcessiveL1Drift)
    );
}

#[test]
fn test_gate_downgrade_excessive_linf_drift() {
    let ep = epoch(50);
    // Default linf threshold = 75_000 (150_000/2). Create single-feature drift > 75_000.
    let bl = snap("bl", normal(), &[("x", 0)], 100, ep);
    let cur = snap("cur", normal(), &[("x", 80_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-linf", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::ExcessiveLinfDrift)
    );
}

#[test]
fn test_gate_downgrade_regime_change() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", elevated(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-regime", &bl, &cur, &budget, &default_cfg(), ep);

    assert_eq!(decision.verdict, GateVerdict::Downgrade);
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::RegimeChanged)
    );
}

#[test]
fn test_gate_downgrade_regime_change_disabled() {
    let ep = epoch(50);
    let cfg = DriftGateConfig {
        regime_change_triggers_downgrade: false,
        ..default_cfg()
    };
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", elevated(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-no-regime-flag", &bl, &cur, &budget, &cfg, ep);
    // regime changed but config says don't downgrade for it
    assert!(decision.is_pass());
}

#[test]
fn test_gate_downgrade_stale_baseline() {
    let ep = epoch(50);
    let old_ep = epoch(1); // 49 epochs ago > default 5
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, old_ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-stale", &bl, &cur, &budget, &default_cfg(), ep);

    assert_eq!(decision.verdict, GateVerdict::Downgrade);
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::StaleBaseline)
    );
    assert_eq!(decision.staleness_epochs, 49);
}

#[test]
fn test_gate_downgrade_budget_exhausted() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(2, ep);
    // Exhaust: 3 transitions > max 2
    budget.record_transition(normal(), elevated(), 1_000, ep);
    budget.record_transition(elevated(), normal(), 1_000, ep);
    budget.record_transition(normal(), normal(), 1_000, ep);
    let decision = evaluate_gate("claim-budget", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::TransitionBudgetExhausted)
    );
}

// ===========================================================================
// Section 9: evaluate_gate — Block
// ===========================================================================

#[test]
fn test_gate_block_l1_drift_plus_budget_exhaustion() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 100_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 900_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(1, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    let decision = evaluate_gate("claim-block", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(decision.is_blocked());
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::ExcessiveL1Drift)
    );
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::TransitionBudgetExhausted)
    );
}

#[test]
fn test_gate_block_three_or_more_reasons() {
    // Stale + regime change + excessive L1 drift = 3 reasons -> block
    let ep = epoch(50);
    let old_ep = epoch(1);
    let bl = snap("bl", normal(), &[("a", 100_000)], 100, old_ep);
    let cur = snap("cur", elevated(), &[("a", 900_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-multiblock", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(decision.is_blocked());
    assert!(decision.reason_count() >= 3);
}

// ===========================================================================
// Section 10: evaluate_gate — Abstain
// ===========================================================================

#[test]
fn test_gate_abstain_insufficient_baseline_observations() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 3, ep);
    let cur = snap("cur", normal(), &[("a", 510_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-insuff-bl", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(decision.is_abstained());
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::InsufficientBaselineObservations)
    );
    assert!(decision.drift.is_none());
}

#[test]
fn test_gate_abstain_insufficient_current_observations() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 510_000)], 5, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-insuff-cur", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(decision.is_abstained());
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::InsufficientCurrentObservations)
    );
}

#[test]
fn test_gate_abstain_both_insufficient() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 2, ep);
    let cur = snap("cur", normal(), &[("a", 510_000)], 3, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-both-insuff", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(decision.is_abstained());
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::InsufficientBaselineObservations)
    );
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::InsufficientCurrentObservations)
    );
}

#[test]
fn test_gate_abstain_no_shared_dimensions() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("only_a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("only_b", 510_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-noshared", &bl, &cur, &budget, &default_cfg(), ep);

    assert!(decision.is_abstained());
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::NoSharedDimensions)
    );
    // drift is computed even though we abstain (the early return includes it)
    assert!(decision.drift.is_some());
}

// ===========================================================================
// Section 11: GateDecision
// ===========================================================================

#[test]
fn test_gate_decision_serde_roundtrip() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("cpu", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("cpu", 510_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-serde", &bl, &cur, &budget, &default_cfg(), ep);

    let json = serde_json::to_string(&decision).unwrap();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn test_gate_decision_content_hash_deterministic() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 100_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 200_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d1 = evaluate_gate("same-claim", &bl, &cur, &budget, &default_cfg(), ep);
    let d2 = evaluate_gate("same-claim", &bl, &cur, &budget, &default_cfg(), ep);
    assert_eq!(d1.content_hash, d2.content_hash);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn test_gate_decision_staleness_computed() {
    let ep = epoch(50);
    let old_ep = epoch(45);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, old_ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-staleness", &bl, &cur, &budget, &default_cfg(), ep);
    assert_eq!(decision.staleness_epochs, 5);
}

#[test]
fn test_gate_decision_budget_fields_populated() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(10, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    let decision = evaluate_gate("claim-bfields", &bl, &cur, &budget, &default_cfg(), ep);

    assert_eq!(decision.budget_remaining, 9);
    assert_eq!(decision.budget_utilization_millionths, 100_000); // 1/10 = 10%
}

// ===========================================================================
// Section 12: batch_evaluate
// ===========================================================================

#[test]
fn test_batch_all_pass() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let result = batch_evaluate(&["c1", "c2", "c3"], &bl, &cur, &budget, &default_cfg(), ep);

    assert_eq!(result.decisions.len(), 3);
    assert_eq!(result.pass_rate_millionths, 1_000_000);
    assert_eq!(result.verdict_counts.get("pass"), Some(&3));
    assert_eq!(result.schema_version, DRIFT_GATE_SCHEMA_VERSION);
}

#[test]
fn test_batch_empty_claims() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let result = batch_evaluate(&[], &bl, &cur, &budget, &default_cfg(), ep);

    assert!(result.decisions.is_empty());
    assert_eq!(result.pass_rate_millionths, 0);
}

#[test]
fn test_batch_mixed_verdicts_pass_rate() {
    let ep = epoch(50);
    // Will fail drift check
    let bl = snap("bl", normal(), &[("a", 100_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 900_000)], 100, ep);
    let budget = fresh_budget(ep);
    let result = batch_evaluate(&["c1"], &bl, &cur, &budget, &default_cfg(), ep);
    assert_eq!(result.pass_rate_millionths, 0); // 0 out of 1 pass
}

#[test]
fn test_batch_serde_roundtrip() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let result = batch_evaluate(&["c1", "c2"], &bl, &bl, &budget, &default_cfg(), ep);
    let json = serde_json::to_string(&result).unwrap();
    let back: BatchGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.decisions.len(), back.decisions.len());
    assert_eq!(result.pass_rate_millionths, back.pass_rate_millionths);
}

#[test]
fn test_batch_content_hash_deterministic() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let r1 = batch_evaluate(&["c1"], &bl, &bl, &budget, &default_cfg(), ep);
    let r2 = batch_evaluate(&["c1"], &bl, &bl, &budget, &default_cfg(), ep);
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ===========================================================================
// Section 13: ClaimScopeLedger
// ===========================================================================

#[test]
fn test_ledger_new_empty() {
    let ep = epoch(1);
    let ledger = ClaimScopeLedger::new(ep);
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.deactivated_count(), 0);
    assert_eq!(ledger.schema_version, DRIFT_GATE_SCHEMA_VERSION);
    assert_eq!(ledger.epoch, ep);
}

#[test]
fn test_ledger_add_and_get_record() {
    let ep = epoch(1);
    let mut ledger = ClaimScopeLedger::new(ep);
    ledger.add_record(make_scope_record("c1", ep));
    ledger.add_record(make_scope_record("c2", ep));

    assert_eq!(ledger.active_count(), 2);
    assert!(ledger.get_record("c1").is_some());
    assert!(ledger.get_record("c2").is_some());
    assert!(ledger.get_record("c3").is_none());
}

#[test]
fn test_ledger_apply_pass_updates_drift() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    ledger.add_record(make_scope_record("c1", ep));

    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 520_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("c1", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(decision.is_pass());

    ledger.apply_decision(&decision);
    let record = ledger.get_record("c1").unwrap();
    assert!(record.active);
    assert!(record.max_passing_drift_millionths > 0);
    assert_eq!(record.last_validated_epoch, ep);
}

#[test]
fn test_ledger_apply_block_deactivates() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    ledger.add_record(make_scope_record("c1", ep));

    let bl = snap("bl", normal(), &[("a", 100_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 900_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(1, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    let decision = evaluate_gate("c1", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(decision.is_blocked());

    ledger.apply_decision(&decision);
    let record = ledger.get_record("c1").unwrap();
    assert!(!record.active);
    assert!(record.deactivation_reason.is_some());
}

#[test]
fn test_ledger_apply_downgrade_stays_active() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    ledger.add_record(make_scope_record("c1", ep));

    // Regime change triggers downgrade, not block
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", elevated(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("c1", &bl, &cur, &budget, &default_cfg(), ep);
    assert_eq!(decision.verdict, GateVerdict::Downgrade);

    ledger.apply_decision(&decision);
    let record = ledger.get_record("c1").unwrap();
    // Downgrade does NOT deactivate
    assert!(record.active);
}

#[test]
fn test_ledger_apply_missing_claim_noop() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    // No record for "c-missing"

    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("c-missing", &bl, &cur, &budget, &default_cfg(), ep);

    // Should not panic
    ledger.apply_decision(&decision);
    assert_eq!(ledger.active_count(), 0);
}

#[test]
fn test_ledger_deactivated_count() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    let mut rec = make_scope_record("c1", ep);
    rec.active = false;
    rec.deactivation_reason = Some(DowngradeReason::ExcessiveL1Drift);
    ledger.add_record(rec);
    ledger.add_record(make_scope_record("c2", ep));

    assert_eq!(ledger.active_count(), 1);
    assert_eq!(ledger.deactivated_count(), 1);
}

// ===========================================================================
// Section 14: Evidence corpus
// ===========================================================================

#[test]
fn test_evidence_corpus_builds_all_families() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    assert_eq!(specimens.len(), 7);
    let families: BTreeSet<DriftGateSpecimenFamily> = specimens.iter().map(|s| s.family).collect();
    assert!(families.contains(&DriftGateSpecimenFamily::StableLowDrift));
    assert!(families.contains(&DriftGateSpecimenFamily::ModerateDrift));
    assert!(families.contains(&DriftGateSpecimenFamily::ExcessiveDrift));
    assert!(families.contains(&DriftGateSpecimenFamily::RegimeChange));
    assert!(families.contains(&DriftGateSpecimenFamily::BudgetExhaustion));
    assert!(families.contains(&DriftGateSpecimenFamily::StaleBaseline));
    assert!(families.contains(&DriftGateSpecimenFamily::InsufficientData));
}

#[test]
fn test_evidence_corpus_verdicts_match_expectations() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    for s in &specimens {
        assert_eq!(
            s.decision.verdict, s.expected_verdict,
            "specimen {} expected {:?}, got {:?}",
            s.id, s.expected_verdict, s.decision.verdict
        );
    }
}

#[test]
fn test_evidence_corpus_deterministic_hash() {
    let (_, h1) = run_evidence_corpus(epoch(50));
    let (_, h2) = run_evidence_corpus(epoch(50));
    assert_eq!(h1, h2);
}

#[test]
fn test_evidence_corpus_unique_ids() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    let ids: BTreeSet<&str> = specimens.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids.len(), specimens.len());
}

#[test]
fn test_evidence_corpus_specimen_serde_roundtrip() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    for s in &specimens {
        let json = serde_json::to_string(s).unwrap();
        let back: DriftGateSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// Section 15: DriftGateSpecimenFamily Display
// ===========================================================================

#[test]
fn test_specimen_family_display_all() {
    let cases = [
        (DriftGateSpecimenFamily::StableLowDrift, "stable_low_drift"),
        (DriftGateSpecimenFamily::ModerateDrift, "moderate_drift"),
        (DriftGateSpecimenFamily::ExcessiveDrift, "excessive_drift"),
        (DriftGateSpecimenFamily::RegimeChange, "regime_change"),
        (
            DriftGateSpecimenFamily::BudgetExhaustion,
            "budget_exhaustion",
        ),
        (DriftGateSpecimenFamily::StaleBaseline, "stale_baseline"),
        (
            DriftGateSpecimenFamily::InsufficientData,
            "insufficient_data",
        ),
    ];
    for (family, expected) in &cases {
        assert_eq!(family.to_string(), *expected);
    }
}

// ===========================================================================
// Section 16: Edge cases and boundary conditions
// ===========================================================================

#[test]
fn test_drift_with_negative_feature_values() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", -100_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 100_000)], 100, ep);
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.l1_drift_millionths, 200_000);
    assert_eq!(d.linf_drift_millionths, 200_000);
}

#[test]
fn test_drift_single_dimension() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("x", 0)], 100, ep);
    let cur = snap("cur", normal(), &[("x", 1_000_000)], 100, ep);
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.l1_drift_millionths, 1_000_000);
    assert_eq!(d.linf_drift_millionths, 1_000_000);
    assert_eq!(d.shared_dimensions, 1);
}

#[test]
fn test_gate_staleness_at_exact_threshold_passes() {
    let ep = epoch(50);
    let boundary_ep = epoch(50 - DEFAULT_MAX_STALENESS_EPOCHS); // exactly at limit
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, boundary_ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-exact-stale", &bl, &cur, &budget, &default_cfg(), ep);
    // staleness == max_staleness_epochs, condition is > not >= so should pass
    assert!(
        !decision
            .downgrade_reasons
            .contains(&DowngradeReason::StaleBaseline)
    );
}

#[test]
fn test_gate_custom_config_tight_thresholds() {
    let ep = epoch(50);
    let cfg = DriftGateConfig {
        max_l1_drift_millionths: 1_000,
        max_linf_drift_millionths: 500,
        max_transitions: 1,
        max_staleness_epochs: 1,
        min_observations: 5,
        regime_change_triggers_downgrade: true,
    };
    let bl = snap("bl", normal(), &[("a", 500_000)], 10, ep);
    let cur = snap("cur", normal(), &[("a", 502_000)], 10, ep);
    let budget = fresh_budget(ep);
    let decision = evaluate_gate("claim-tight", &bl, &cur, &budget, &cfg, ep);
    // drift of 2000 > threshold 1000 -> downgrade
    assert!(
        decision
            .downgrade_reasons
            .contains(&DowngradeReason::ExcessiveL1Drift)
    );
}

#[test]
fn test_transition_event_fields() {
    let mut b = TransitionBudgetTracker::new(10, epoch(1));
    b.record_transition(normal(), elevated(), 42_000, epoch(5));
    let ev = &b.history[0];
    assert_eq!(ev.sequence, 1);
    assert_eq!(ev.from_regime, normal());
    assert_eq!(ev.to_regime, elevated());
    assert_eq!(ev.drift_at_transition_millionths, 42_000);
    assert_eq!(ev.epoch, epoch(5));
}

#[test]
fn test_snapshot_zero_observations() {
    let s = snap("z", normal(), &[("a", 100)], 0, epoch(1));
    assert!(!s.is_trustworthy());
    assert_eq!(s.observation_count, 0);
}

#[test]
fn test_budget_many_transitions_saturating() {
    let mut b = TransitionBudgetTracker::new(3, epoch(1));
    for i in 0..100 {
        b.record_transition(normal(), normal(), 0, epoch(i + 2));
    }
    assert!(!b.is_within_budget());
    assert_eq!(b.remaining(), 0);
    assert_eq!(b.history.len(), 100);
}
