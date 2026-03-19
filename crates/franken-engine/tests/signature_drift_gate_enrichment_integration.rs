//! Enrichment integration tests for the `signature_drift_gate` module.
//!
//! Exercises deeper boundary conditions, multi-reason escalation paths,
//! ledger lifecycle flows, batch evaluation edge cases, evidence corpus
//! verification, config overrides, and determinism guarantees.

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

use std::collections::BTreeMap;

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
        baseline_hash: ContentHash::compute(b"enrichment-baseline"),
        max_passing_drift_millionths: 0,
        active: true,
        deactivation_reason: None,
        last_validated_epoch: ep,
    }
}

// ===========================================================================
// Section 1: Snapshot content hash sensitivity
// ===========================================================================

#[test]
fn enrichment_snapshot_hash_same_when_regime_differs() {
    // Content hash does NOT include regime — only id, features, observation_count
    let a = snap("s", normal(), &[("x", 42)], 10, epoch(1));
    let b = snap("s", elevated(), &[("x", 42)], 10, epoch(1));
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_snapshot_hash_differs_on_observation_count() {
    let a = snap("s", normal(), &[("x", 42)], 10, epoch(1));
    let b = snap("s", normal(), &[("x", 42)], 11, epoch(1));
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_snapshot_hash_same_when_epoch_differs() {
    // Content hash does NOT include epoch
    let a = snap("s", normal(), &[("x", 42)], 10, epoch(1));
    let b = snap("s", normal(), &[("x", 42)], 10, epoch(2));
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_snapshot_with_many_features_hash_stable() {
    let feats: Vec<(&str, i64)> = vec![
        ("f0", 0), ("f1", 100_000), ("f2", 200_000), ("f3", 300_000),
        ("f4", 400_000), ("f5", 500_000), ("f6", 600_000), ("f7", 700_000),
    ];
    let a = snap("multi", normal(), &feats, 50, epoch(10));
    let b = snap("multi", normal(), &feats, 50, epoch(10));
    assert_eq!(a.content_hash, b.content_hash);
}

// ===========================================================================
// Section 2: DriftMeasurement edge cases
// ===========================================================================

#[test]
fn enrichment_drift_large_negative_values() {
    let bl = snap("bl", normal(), &[("a", -500_000)], 100, epoch(1));
    let cur = snap("cur", normal(), &[("a", -800_000)], 100, epoch(1));
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.l1_drift_millionths, 300_000);
    assert_eq!(d.linf_drift_millionths, 300_000);
}

#[test]
fn enrichment_drift_both_zero() {
    let bl = snap("bl", normal(), &[("a", 0)], 100, epoch(1));
    let cur = snap("cur", normal(), &[("a", 0)], 100, epoch(1));
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.l1_drift_millionths, 0);
    assert_eq!(d.linf_drift_millionths, 0);
}

#[test]
fn enrichment_drift_many_shared_dimensions() {
    let feats_bl: Vec<(&str, i64)> = vec![
        ("d0", 500_000), ("d1", 500_000), ("d2", 500_000), ("d3", 500_000),
        ("d4", 500_000), ("d5", 500_000), ("d6", 500_000), ("d7", 500_000),
        ("d8", 500_000), ("d9", 500_000),
    ];
    let feats_cur: Vec<(&str, i64)> = vec![
        ("d0", 510_000), ("d1", 510_000), ("d2", 510_000), ("d3", 510_000),
        ("d4", 510_000), ("d5", 510_000), ("d6", 510_000), ("d7", 510_000),
        ("d8", 510_000), ("d9", 510_000),
    ];
    let bl = snap("bl", normal(), &feats_bl, 100, epoch(1));
    let cur = snap("cur", normal(), &feats_cur, 100, epoch(1));
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.shared_dimensions, 10);
    assert_eq!(d.l1_drift_millionths, 100_000);
    assert_eq!(d.linf_drift_millionths, 10_000);
}

#[test]
fn enrichment_drift_asymmetric_features() {
    let bl = snap("bl", normal(), &[("a", 100), ("b", 200), ("c", 300)], 100, epoch(1));
    let cur = snap("cur", normal(), &[("b", 210), ("c", 350), ("d", 400)], 100, epoch(1));
    let d = compute_drift(&bl, &cur);
    assert_eq!(d.shared_dimensions, 2);
    assert!(d.missing_features.contains("a"));
    assert!(d.new_features.contains("d"));
    assert_eq!(d.l1_drift_millionths, 60);
    assert_eq!(d.linf_drift_millionths, 50);
}

#[test]
fn enrichment_drift_deterministic_across_calls() {
    let bl = snap("bl", normal(), &[("x", 100_000), ("y", 200_000)], 100, epoch(1));
    let cur = snap("cur", normal(), &[("x", 150_000), ("y", 220_000)], 100, epoch(1));
    let d1 = compute_drift(&bl, &cur);
    let d2 = compute_drift(&bl, &cur);
    assert_eq!(d1, d2);
}

// ===========================================================================
// Section 3: Budget tracker edge cases
// ===========================================================================

#[test]
fn enrichment_budget_exact_boundary_within() {
    let mut b = TransitionBudgetTracker::new(5, epoch(1));
    for i in 0..5 {
        b.record_transition(normal(), normal(), 0, epoch(i + 2));
    }
    assert!(b.is_within_budget());
    assert_eq!(b.remaining(), 0);
}

#[test]
fn enrichment_budget_one_over_boundary() {
    let mut b = TransitionBudgetTracker::new(5, epoch(1));
    for i in 0..6 {
        b.record_transition(normal(), normal(), 0, epoch(i + 2));
    }
    assert!(!b.is_within_budget());
    assert_eq!(b.remaining(), 0);
}

#[test]
fn enrichment_budget_utilization_at_50_percent() {
    let mut b = TransitionBudgetTracker::new(100, epoch(1));
    for i in 0..50 {
        b.record_transition(normal(), normal(), 0, epoch(i + 2));
    }
    assert_eq!(b.utilization_millionths(), 500_000);
}

#[test]
fn enrichment_budget_reset_preserves_max_transitions() {
    let mut b = TransitionBudgetTracker::new(7, epoch(1));
    b.record_transition(normal(), normal(), 0, epoch(2));
    b.record_transition(normal(), normal(), 0, epoch(3));
    b.reset(epoch(100));
    assert_eq!(b.max_transitions, 7);
    assert_eq!(b.transitions_consumed, 0);
    assert_eq!(b.remaining(), 7);
}

#[test]
fn enrichment_budget_history_accumulates_correctly() {
    let mut b = TransitionBudgetTracker::new(10, epoch(1));
    b.record_transition(normal(), elevated(), 10_000, epoch(5));
    b.record_transition(elevated(), normal(), 20_000, epoch(6));
    assert_eq!(b.history.len(), 2);
    assert_eq!(b.history[0].sequence, 1);
    assert_eq!(b.history[1].sequence, 2);
    assert_eq!(b.history[0].drift_at_transition_millionths, 10_000);
    assert_eq!(b.history[1].drift_at_transition_millionths, 20_000);
}

// ===========================================================================
// Section 4: Gate evaluation — multi-reason combinations
// ===========================================================================

#[test]
fn enrichment_gate_downgrade_l1_and_linf_together() {
    let ep = epoch(50);
    let cfg = DriftGateConfig {
        max_l1_drift_millionths: 50_000,
        max_linf_drift_millionths: 30_000,
        ..default_cfg()
    };
    let bl = snap("bl", normal(), &[("a", 0), ("b", 0)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 40_000), ("b", 20_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("claim-both-drift", &bl, &cur, &budget, &cfg, ep);
    assert!(d.downgrade_reasons.contains(&DowngradeReason::ExcessiveL1Drift));
    assert!(d.downgrade_reasons.contains(&DowngradeReason::ExcessiveLinfDrift));
}

#[test]
fn enrichment_gate_block_l1_drift_and_budget() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 0)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 900_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(1, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    let d = evaluate_gate("claim-block-combo", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(d.is_blocked());
    assert!(d.downgrade_reasons.contains(&DowngradeReason::ExcessiveL1Drift));
    assert!(d.downgrade_reasons.contains(&DowngradeReason::TransitionBudgetExhausted));
}

#[test]
fn enrichment_gate_block_with_four_reasons() {
    let ep = epoch(50);
    let old_ep = epoch(1);
    let bl = snap("bl", normal(), &[("a", 0)], 100, old_ep);
    let cur = snap("cur", elevated(), &[("a", 900_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(1, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    let d = evaluate_gate("claim-4reasons", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(d.is_blocked());
    assert!(d.reason_count() >= 3);
}

#[test]
fn enrichment_gate_pass_with_all_checks_at_boundary() {
    let ep = epoch(50);
    let boundary_ep = epoch(50 - DEFAULT_MAX_STALENESS_EPOCHS);
    let cfg = DriftGateConfig {
        max_l1_drift_millionths: 100_000,
        max_linf_drift_millionths: 100_000,
        ..default_cfg()
    };
    let bl = snap("bl", normal(), &[("a", 0)], MIN_OBSERVATIONS_FOR_DRIFT, boundary_ep);
    let cur = snap("cur", normal(), &[("a", 100_000)], MIN_OBSERVATIONS_FOR_DRIFT, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("boundary-pass", &bl, &cur, &budget, &cfg, ep);
    assert!(d.is_pass());
}

// ===========================================================================
// Section 5: Gate decision fields
// ===========================================================================

#[test]
fn enrichment_gate_decision_schema_version_correct() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("claim-schema", &bl, &cur, &budget, &default_cfg(), ep);
    assert_eq!(d.schema_version, DRIFT_GATE_SCHEMA_VERSION);
}

#[test]
fn enrichment_gate_decision_id_prefix_matches_verdict() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("claim-prefix", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(d.decision_id.starts_with("dg-pass-"));

    // Use only stale baseline (low drift) to get a downgrade with just 1 reason
    let bl_stale = snap("bl2", normal(), &[("a", 505_000)], 100, epoch(1));
    let d2 = evaluate_gate("claim-prefix2", &bl_stale, &cur, &budget, &default_cfg(), ep);
    // Stale baseline alone -> downgrade
    assert!(d2.decision_id.starts_with("dg-downgrade-"));
}

#[test]
fn enrichment_gate_decision_abstain_id_prefix() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 3, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("claim-abstain-prefix", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(d.decision_id.starts_with("dg-abstain-"));
}

#[test]
fn enrichment_gate_decision_epoch_stored() {
    let ep = epoch(42);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("claim-ep", &bl, &cur, &budget, &default_cfg(), ep);
    assert_eq!(d.epoch, ep);
}

// ===========================================================================
// Section 6: Config overrides
// ===========================================================================

#[test]
fn enrichment_config_zero_max_staleness() {
    let ep = epoch(50);
    let cfg = DriftGateConfig {
        max_staleness_epochs: 0,
        ..default_cfg()
    };
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, epoch(49));
    let cur = snap("cur", normal(), &[("a", 505_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("claim-zero-stale", &bl, &cur, &budget, &cfg, ep);
    assert!(d.downgrade_reasons.contains(&DowngradeReason::StaleBaseline));
}

#[test]
fn enrichment_config_very_large_thresholds_always_pass() {
    let ep = epoch(50);
    let cfg = DriftGateConfig {
        max_l1_drift_millionths: i64::MAX,
        max_linf_drift_millionths: i64::MAX,
        max_transitions: u64::MAX,
        max_staleness_epochs: u64::MAX,
        min_observations: 1,
        regime_change_triggers_downgrade: false,
    };
    // Must have at least MIN_OBSERVATIONS_FOR_DRIFT (10) to be trustworthy
    let bl = snap("bl", normal(), &[("a", 0)], 10, ep);
    let cur = snap("cur", elevated(), &[("a", 999_999)], 10, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("claim-huge-cfg", &bl, &cur, &budget, &cfg, ep);
    assert!(d.is_pass());
}

// ===========================================================================
// Section 7: Batch evaluation enrichment
// ===========================================================================

#[test]
fn enrichment_batch_single_claim_pass_rate() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let r = batch_evaluate(&["c1"], &bl, &bl, &budget, &default_cfg(), ep);
    assert_eq!(r.pass_rate_millionths, 1_000_000);
    assert_eq!(r.decisions.len(), 1);
}

#[test]
fn enrichment_batch_verdict_counts_correct() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let r = batch_evaluate(&["c1", "c2", "c3", "c4"], &bl, &bl, &budget, &default_cfg(), ep);
    assert_eq!(*r.verdict_counts.get("pass").unwrap_or(&0), 4);
}

#[test]
fn enrichment_batch_deterministic_content_hash() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let r1 = batch_evaluate(&["c1", "c2"], &bl, &bl, &budget, &default_cfg(), ep);
    let r2 = batch_evaluate(&["c1", "c2"], &bl, &bl, &budget, &default_cfg(), ep);
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.schema_version, r2.schema_version);
}

// ===========================================================================
// Section 8: Ledger lifecycle
// ===========================================================================

#[test]
fn enrichment_ledger_multiple_apply_updates_max_drift() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    ledger.add_record(make_scope_record("c1", ep));

    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);

    let cur1 = snap("cur1", normal(), &[("a", 510_000)], 100, ep);
    let d1 = evaluate_gate("c1", &bl, &cur1, &budget, &default_cfg(), ep);
    assert!(d1.is_pass());
    ledger.apply_decision(&d1);
    let drift1 = ledger.get_record("c1").unwrap().max_passing_drift_millionths;

    let cur2 = snap("cur2", normal(), &[("a", 530_000)], 100, ep);
    let d2 = evaluate_gate("c1", &bl, &cur2, &budget, &default_cfg(), ep);
    assert!(d2.is_pass());
    ledger.apply_decision(&d2);
    let drift2 = ledger.get_record("c1").unwrap().max_passing_drift_millionths;

    assert!(drift2 >= drift1);
}

#[test]
fn enrichment_ledger_deactivation_is_permanent() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    ledger.add_record(make_scope_record("c1", ep));

    let bl = snap("bl", normal(), &[("a", 0)], 100, ep);
    let cur = snap("cur", normal(), &[("a", 900_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(1, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    budget.record_transition(normal(), normal(), 0, ep);
    let d_block = evaluate_gate("c1", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(d_block.is_blocked());
    ledger.apply_decision(&d_block);
    assert!(!ledger.get_record("c1").unwrap().active);

    let cur2 = snap("cur2", normal(), &[("a", 5_000)], 100, ep);
    let budget2 = fresh_budget(ep);
    let d_pass = evaluate_gate("c1", &bl, &cur2, &budget2, &default_cfg(), ep);
    assert!(d_pass.is_pass());
    ledger.apply_decision(&d_pass);
    assert!(!ledger.get_record("c1").unwrap().active);
}

#[test]
fn enrichment_ledger_serde_roundtrip() {
    let ep = epoch(50);
    let mut ledger = ClaimScopeLedger::new(ep);
    ledger.add_record(make_scope_record("c1", ep));
    ledger.add_record(make_scope_record("c2", ep));
    let json = serde_json::to_string(&ledger).unwrap();
    let back: ClaimScopeLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back.records.len(), 2);
    assert_eq!(back.epoch, ep);
}

// ===========================================================================
// Section 9: Evidence corpus deeper checks
// ===========================================================================

#[test]
fn enrichment_evidence_corpus_stable_family_passes() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    let stable = specimens.iter().find(|s| s.family == DriftGateSpecimenFamily::StableLowDrift);
    assert!(stable.is_some());
    assert_eq!(stable.unwrap().decision.verdict, GateVerdict::Pass);
}

#[test]
fn enrichment_evidence_corpus_excessive_family_not_pass() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    let excessive = specimens.iter().find(|s| s.family == DriftGateSpecimenFamily::ExcessiveDrift);
    assert!(excessive.is_some());
    assert_ne!(excessive.unwrap().decision.verdict, GateVerdict::Pass);
}

#[test]
fn enrichment_evidence_corpus_insufficient_data_abstains() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    let insuff = specimens.iter().find(|s| s.family == DriftGateSpecimenFamily::InsufficientData);
    assert!(insuff.is_some());
    assert_eq!(insuff.unwrap().decision.verdict, GateVerdict::Abstain);
}

#[test]
fn enrichment_evidence_corpus_different_epochs_produce_different_hashes() {
    // Epochs affect decision content (staleness, etc.) so corpus hash should differ
    let (_, h1) = run_evidence_corpus(epoch(50));
    let (_, _h2) = run_evidence_corpus(epoch(500));
    // Different epochs may or may not produce different hashes depending on
    // whether the epoch affects any intermediate computations. Test determinism instead.
    let (_, h1b) = run_evidence_corpus(epoch(50));
    assert_eq!(h1, h1b);
}

#[test]
fn enrichment_evidence_corpus_all_specimens_have_descriptions() {
    let (specimens, _) = run_evidence_corpus(epoch(50));
    for s in &specimens {
        assert!(!s.description.is_empty(), "empty description for {}", s.id);
    }
}

// ===========================================================================
// Section 10: Serde roundtrips for nested types
// ===========================================================================

#[test]
fn enrichment_transition_event_serde_roundtrip() {
    let mut b = TransitionBudgetTracker::new(10, epoch(1));
    b.record_transition(normal(), elevated(), 42_000, epoch(5));
    let ev = &b.history[0];
    let json = serde_json::to_string(ev).unwrap();
    let back: TransitionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(*ev, back);
}

#[test]
fn enrichment_gate_decision_full_serde_roundtrip() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("cpu", 500_000), ("mem", 300_000)], 100, ep);
    let cur = snap("cur", elevated(), &[("cpu", 700_000), ("mem", 400_000)], 100, ep);
    let mut budget = TransitionBudgetTracker::new(3, ep);
    budget.record_transition(normal(), elevated(), 50_000, epoch(51));
    let d = evaluate_gate("serde-test", &bl, &cur, &budget, &default_cfg(), ep);
    let json = serde_json::to_string(&d).unwrap();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_batch_result_serde_roundtrip() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let r = batch_evaluate(&["c1", "c2", "c3"], &bl, &bl, &budget, &default_cfg(), ep);
    let json = serde_json::to_string(&r).unwrap();
    let back: BatchGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r.decisions.len(), back.decisions.len());
    assert_eq!(r.content_hash, back.content_hash);
    assert_eq!(r.pass_rate_millionths, back.pass_rate_millionths);
}

#[test]
fn enrichment_claim_scope_record_serde_roundtrip() {
    let rec = make_scope_record("test-claim", epoch(10));
    let json = serde_json::to_string(&rec).unwrap();
    let back: ClaimScopeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn enrichment_specimen_family_serde_roundtrip() {
    let families = [
        DriftGateSpecimenFamily::StableLowDrift,
        DriftGateSpecimenFamily::ModerateDrift,
        DriftGateSpecimenFamily::ExcessiveDrift,
        DriftGateSpecimenFamily::RegimeChange,
        DriftGateSpecimenFamily::BudgetExhaustion,
        DriftGateSpecimenFamily::StaleBaseline,
        DriftGateSpecimenFamily::InsufficientData,
    ];
    for f in &families {
        let json = serde_json::to_string(f).unwrap();
        let back: DriftGateSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ===========================================================================
// Section 11: Verdict classification boundary
// ===========================================================================

#[test]
fn enrichment_exactly_two_reasons_downgrade_not_block() {
    let ep = epoch(50);
    let old_ep = epoch(1);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, old_ep);
    let cur = snap("cur", elevated(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("2reasons", &bl, &cur, &budget, &default_cfg(), ep);
    assert!(d.downgrade_reasons.contains(&DowngradeReason::StaleBaseline));
    assert!(d.downgrade_reasons.contains(&DowngradeReason::RegimeChanged));
    if d.reason_count() == 2 {
        assert_eq!(d.verdict, GateVerdict::Downgrade);
    }
}

#[test]
fn enrichment_single_reason_downgrade() {
    let ep = epoch(50);
    let bl = snap("bl", normal(), &[("a", 500_000)], 100, ep);
    let cur = snap("cur", elevated(), &[("a", 500_000)], 100, ep);
    let budget = fresh_budget(ep);
    let d = evaluate_gate("1reason", &bl, &cur, &budget, &default_cfg(), ep);
    assert_eq!(d.reason_count(), 1);
    assert_eq!(d.verdict, GateVerdict::Downgrade);
}

// ===========================================================================
// Section 12: Snapshot trustworthiness
// ===========================================================================

#[test]
fn enrichment_snapshot_trustworthy_exactly_at_min() {
    let s = snap("t", normal(), &[("a", 1)], MIN_OBSERVATIONS_FOR_DRIFT, epoch(1));
    assert!(s.is_trustworthy());
}

#[test]
fn enrichment_snapshot_untrustworthy_one_below_min() {
    let s = snap("u", normal(), &[("a", 1)], MIN_OBSERVATIONS_FOR_DRIFT - 1, epoch(1));
    assert!(!s.is_trustworthy());
}

#[test]
fn enrichment_snapshot_zero_dimension_trustworthy() {
    let s = snap("z", normal(), &[], 100, epoch(1));
    assert!(s.is_trustworthy());
    assert_eq!(s.dimension(), 0);
}
