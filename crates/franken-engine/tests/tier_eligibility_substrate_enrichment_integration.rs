//! Enrichment integration tests for `tier_eligibility_substrate` module.
//!
//! Bead: bd-1lsy.4.11.2 [RGC-310B]
//!
//! Covers arithmetic edge cases, cooldown boundaries, confidence computation
//! extremes, policy configuration limits, feedback stability edge cases,
//! report aggregation stress, and determinism verification.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tier_eligibility_substrate::{
    COMPONENT, DeoptReason, ExecutionTier, ProbeKind, TIER_ELIGIBILITY_BEAD_ID,
    TIER_ELIGIBILITY_POLICY_ID, TIER_ELIGIBILITY_SCHEMA_VERSION, TierEligibilityPolicy,
    TierProfile, add_probe, build_eligibility_report, compute_deopt_rate, cooldown_active,
    evaluate_eligibility, franken_engine_tier_eligibility_manifest, is_feedback_stable,
    record_deopt, tier_rank,
};

fn default_policy() -> TierEligibilityPolicy {
    TierEligibilityPolicy::default()
}

fn warm_baseline_profile(invocations: u64, stable_probes: u64) -> TierProfile {
    let mut p = TierProfile::new("warm-base", "fn_warm");
    p.current_tier = ExecutionTier::Baseline;
    p.invocation_count = invocations;
    for i in 0..stable_probes {
        add_probe(
            &mut p,
            ProbeKind::TypeProfile,
            &format!("site-{i}"),
            100,
            900_000,
        );
    }
    p.rehash();
    p
}

// =========================================================================
// Arithmetic edge cases: compute_deopt_rate
// =========================================================================

#[test]
fn deopt_rate_zero_invocations_zero_deopts() {
    let p = TierProfile::new("dr0", "fn_zero");
    assert_eq!(compute_deopt_rate(&p), 0);
}

#[test]
fn deopt_rate_one_invocation_one_deopt() {
    let mut p = TierProfile::new("dr1", "fn_one");
    p.invocation_count = 1;
    p.deopt_count = 1;
    p.rehash();
    // 1 * 1_000_000 / 1 = 1_000_000 (100%)
    assert_eq!(compute_deopt_rate(&p), 1_000_000);
}

#[test]
fn deopt_rate_large_invocations_small_deopts() {
    let mut p = TierProfile::new("dr2", "fn_large");
    p.invocation_count = 1_000_000;
    p.deopt_count = 1;
    p.rehash();
    // 1 * 1_000_000 / 1_000_000 = 1 (0.0001%)
    assert_eq!(compute_deopt_rate(&p), 1);
}

#[test]
fn deopt_rate_saturation_at_u64_max() {
    let mut p = TierProfile::new("dr3", "fn_max");
    p.invocation_count = 1;
    p.deopt_count = u64::MAX;
    p.rehash();
    // u64::MAX.saturating_mul(1_000_000) → u64::MAX, then u64::MAX / 1 → u64::MAX
    let rate = compute_deopt_rate(&p);
    assert_eq!(rate, u64::MAX);
}

#[test]
fn deopt_rate_both_very_large() {
    let mut p = TierProfile::new("dr4", "fn_both_large");
    // Use values that don't overflow when multiplied by 1_000_000
    // max safe deopt_count: u64::MAX / 1_000_000 ≈ 18_446_744_073_709
    p.invocation_count = 10_000_000;
    p.deopt_count = 5_000_000;
    p.rehash();
    let rate = compute_deopt_rate(&p);
    // 5_000_000 * 1_000_000 / 10_000_000 = 500_000 (50%)
    assert_eq!(rate, 500_000);
}

// =========================================================================
// Cooldown boundary conditions
// =========================================================================

#[test]
fn cooldown_no_events_is_inactive() {
    let p = TierProfile::new("cd0", "fn_no_events");
    let epoch = SecurityEpoch::from_raw(100);
    assert!(!cooldown_active(&p, 3, &epoch));
}

#[test]
fn cooldown_exactly_at_boundary() {
    let mut p = TierProfile::new("cd1", "fn_boundary");
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(97),
    );
    // Cooldown = 3 epochs. Deopt at 97. Current at 100.
    // 100 - 97 = 3, which is NOT < 3, so cooldown should be inactive
    assert!(!cooldown_active(&p, 3, &SecurityEpoch::from_raw(100)));
}

#[test]
fn cooldown_one_before_boundary() {
    let mut p = TierProfile::new("cd2", "fn_one_before");
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(98),
    );
    // 100 - 98 = 2 < 3, so cooldown IS active
    assert!(cooldown_active(&p, 3, &SecurityEpoch::from_raw(100)));
}

#[test]
fn cooldown_at_same_epoch() {
    let mut p = TierProfile::new("cd3", "fn_same");
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(100),
    );
    // 100 - 100 = 0 < 3, so cooldown IS active
    assert!(cooldown_active(&p, 3, &SecurityEpoch::from_raw(100)));
}

#[test]
fn cooldown_zero_epochs_always_inactive() {
    let mut p = TierProfile::new("cd4", "fn_zero_cd");
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(100),
    );
    // 100 - 100 = 0, is 0 < 0? No. So cooldown should be inactive
    assert!(!cooldown_active(&p, 0, &SecurityEpoch::from_raw(100)));
}

#[test]
fn cooldown_very_large_window() {
    let mut p = TierProfile::new("cd5", "fn_large_cd");
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(0),
    );
    // Even with epoch 1000, u64::MAX cooldown means cooldown is always active
    assert!(cooldown_active(
        &p,
        u64::MAX,
        &SecurityEpoch::from_raw(1000)
    ));
}

#[test]
fn cooldown_multiple_events_earliest_matters() {
    let mut p = TierProfile::new("cd6", "fn_multi_events");
    p.current_tier = ExecutionTier::Optimized;
    p.invocation_count = 500;
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(90),
    );
    p.current_tier = ExecutionTier::Baseline; // manually set back
    record_deopt(
        &mut p,
        DeoptReason::BoundsCheck,
        "site_1",
        &SecurityEpoch::from_raw(99),
    );
    // Cooldown 3. Most recent deopt at 99. Current at 101.
    // 101 - 99 = 2 < 3 → active (most recent deopt matters)
    assert!(cooldown_active(&p, 3, &SecurityEpoch::from_raw(101)));
    // Check after cooldown expires for most recent event
    // 103 - 99 = 4 >= 3 AND 103 - 90 = 13 >= 3 → inactive
    assert!(!cooldown_active(&p, 3, &SecurityEpoch::from_raw(103)));
}

#[test]
fn cooldown_epoch_zero() {
    let mut p = TierProfile::new("cd7", "fn_epoch0");
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(0),
    );
    // Cooldown 3. Deopt at 0. Check at 0: 0-0=0 < 3 → active
    assert!(cooldown_active(&p, 3, &SecurityEpoch::from_raw(0)));
    // Check at 3: 3-0=3, 3 < 3 is false → inactive
    assert!(!cooldown_active(&p, 3, &SecurityEpoch::from_raw(3)));
}

// =========================================================================
// Feedback stability edge cases
// =========================================================================

#[test]
fn feedback_stability_no_probes() {
    let p = TierProfile::new("fs0", "fn_no_probes");
    assert!(!is_feedback_stable(&p, 10, 800_000));
}

#[test]
fn feedback_stability_all_above_threshold() {
    let mut p = TierProfile::new("fs1", "fn_all_above");
    for i in 0..5 {
        add_probe(&mut p, ProbeKind::TypeProfile, &format!("s{i}"), 100, 0);
    }
    assert!(is_feedback_stable(&p, 10, 1_000_000)); // 100% threshold
}

#[test]
fn feedback_stability_all_below_threshold() {
    let mut p = TierProfile::new("fs2", "fn_all_below");
    for i in 0..5 {
        add_probe(&mut p, ProbeKind::TypeProfile, &format!("s{i}"), 5, 0);
    }
    // min_probe_samples=10, all have 5 → 0% stability
    assert!(!is_feedback_stable(&p, 10, 1));
}

#[test]
fn feedback_stability_exact_boundary() {
    let mut p = TierProfile::new("fs3", "fn_exact");
    // 4 probes with enough samples, 1 without → 4/5 = 800_000
    for i in 0..4 {
        add_probe(&mut p, ProbeKind::TypeProfile, &format!("s{i}"), 10, 0);
    }
    add_probe(&mut p, ProbeKind::TypeProfile, "s4", 9, 0);
    // Threshold 800_000 (80%), actual 800_000 → should pass (>=)
    assert!(is_feedback_stable(&p, 10, 800_000));
}

#[test]
fn feedback_stability_just_below_boundary() {
    let mut p = TierProfile::new("fs4", "fn_just_below");
    // 3 probes with enough samples, 2 without → 3/5 = 600_000
    for i in 0..3 {
        add_probe(&mut p, ProbeKind::TypeProfile, &format!("s{i}"), 10, 0);
    }
    for i in 3..5 {
        add_probe(&mut p, ProbeKind::TypeProfile, &format!("s{i}"), 9, 0);
    }
    assert!(!is_feedback_stable(&p, 10, 800_000));
}

#[test]
fn feedback_stability_zero_threshold_accepts_any() {
    let mut p = TierProfile::new("fs5", "fn_zero_thresh");
    add_probe(&mut p, ProbeKind::TypeProfile, "s0", 0, 0);
    // Even with 0 samples, stability >= 0 is true
    assert!(is_feedback_stable(&p, 0, 0));
}

#[test]
fn feedback_stability_single_probe_at_exact_min() {
    let mut p = TierProfile::new("fs6", "fn_single_exact");
    add_probe(&mut p, ProbeKind::TypeProfile, "s0", 10, 0);
    // 1/1 = 1_000_000 >= 1_000_000
    assert!(is_feedback_stable(&p, 10, 1_000_000));
}

#[test]
fn feedback_stability_mixed_probe_kinds() {
    let mut p = TierProfile::new("fs7", "fn_mixed_kinds");
    add_probe(&mut p, ProbeKind::TypeProfile, "s0", 100, 0);
    add_probe(&mut p, ProbeKind::AllocationSite, "s1", 100, 0);
    add_probe(&mut p, ProbeKind::BranchCoverage, "s2", 100, 0);
    add_probe(&mut p, ProbeKind::CallFrequency, "s3", 100, 0);
    add_probe(&mut p, ProbeKind::InlineCacheState, "s4", 100, 0);
    assert!(is_feedback_stable(&p, 10, 1_000_000));
}

// =========================================================================
// evaluate_eligibility edge cases
// =========================================================================

#[test]
fn eligibility_specialized_is_ineligible() {
    let policy = default_policy();
    let mut p = TierProfile::new("el0", "fn_specialized");
    p.current_tier = ExecutionTier::Specialized;
    p.invocation_count = 10000;
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
    assert!(v.probe_summary.contains("highest tier"));
}

#[test]
fn eligibility_deoptimized_targets_interpreted() {
    let policy = default_policy();
    let mut p = TierProfile::new("el1", "fn_deopt");
    p.current_tier = ExecutionTier::Deoptimized;
    p.invocation_count = 500;
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert_eq!(v.target_tier, ExecutionTier::Interpreted);
}

#[test]
fn eligibility_interpreted_to_baseline_no_feedback_needed() {
    let policy = default_policy();
    let mut p = TierProfile::new("el2", "fn_interp");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 500;
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    // Interpreted → Baseline doesn't require feedback stability
    assert!(v.eligible);
    assert_eq!(v.target_tier, ExecutionTier::Baseline);
}

#[test]
fn eligibility_baseline_to_optimized_needs_feedback() {
    let policy = default_policy();
    let mut p = TierProfile::new("el3", "fn_base_no_feedback");
    p.current_tier = ExecutionTier::Baseline;
    p.invocation_count = 500;
    // No probes → feedback not stable → ineligible
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
}

#[test]
fn eligibility_high_deopt_rate_blocks() {
    let policy = default_policy();
    let mut p = TierProfile::new("el4", "fn_high_deopt");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 200;
    p.deopt_count = 20; // 20/200 = 100_000 > 50_000
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
    assert!(v.probe_summary.contains("deopt_rate"));
}

#[test]
fn eligibility_lifetime_deopts_exceeded() {
    let policy = default_policy();
    let mut p = TierProfile::new("el5", "fn_lifetime_deopt");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 500;
    p.deopt_count = 11; // > 10 (max_lifetime_deopts)
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
    assert!(v.probe_summary.contains("lifetime_deopts"));
}

#[test]
fn eligibility_confidence_zero_when_ineligible() {
    let policy = default_policy();
    let mut p = TierProfile::new("el6", "fn_ineligible_conf");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 5; // too low
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
    assert_eq!(v.confidence_millionths, 0);
}

#[test]
fn eligibility_with_cooldown_active() {
    let mut p = TierProfile::new("el7", "fn_cooldown");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 500;
    // Record deopt at epoch 0, profile's last_transition_epoch will be 0
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "s0",
        &SecurityEpoch::from_raw(0),
    );
    // Set back to interpreted at same epoch
    p.current_tier = ExecutionTier::Interpreted;
    p.last_transition_epoch = SecurityEpoch::from_raw(0); // cooldown checks against this
    p.rehash();
    let policy = default_policy();
    let v = evaluate_eligibility(&p, &policy);
    // Cooldown: 0 - 0 = 0 < 3 → active → rejected
    assert!(!v.eligible);
}

// =========================================================================
// Confidence computation edge cases
// =========================================================================

#[test]
fn confidence_high_with_ideal_profile() {
    let p = warm_baseline_profile(1000, 10);
    let policy = default_policy();
    let v = evaluate_eligibility(&p, &policy);
    assert!(v.eligible);
    // High invocations, all probes stable, no deopts → high confidence
    assert!(
        v.confidence_millionths > 800_000,
        "expected high confidence, got {}",
        v.confidence_millionths
    );
}

#[test]
fn confidence_moderate_with_few_invocations() {
    // Exactly at min_invocations → inv_factor = 100/200 * M = 500_000
    let p = warm_baseline_profile(100, 5);
    let policy = default_policy();
    let v = evaluate_eligibility(&p, &policy);
    assert!(v.eligible);
    assert!(
        v.confidence_millionths < 900_000,
        "expected moderate confidence, got {}",
        v.confidence_millionths
    );
}

#[test]
fn confidence_no_probes_gives_partial_credit() {
    // Interpreted → Baseline doesn't require feedback, so we can test partial credit
    let mut p = TierProfile::new("conf2", "fn_no_probes");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 500;
    p.rehash();
    let policy = default_policy();
    let v = evaluate_eligibility(&p, &policy);
    assert!(v.eligible);
    // No probes → feedback_factor = MILLIONTHS/2 = 500_000
    // So overall confidence should be moderate
    assert!(v.confidence_millionths > 0);
}

// =========================================================================
// Policy configuration extremes
// =========================================================================

#[test]
fn policy_zero_min_invocations_accepts_all() {
    let policy = TierEligibilityPolicy {
        min_invocations: 0,
        ..default_policy()
    };
    let mut p = TierProfile::new("pz0", "fn_zero_inv");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 0;
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    // 0 invocations >= 0 min → passes invocation check
    assert!(v.eligible);
}

#[test]
fn policy_zero_max_deopt_rate_any_deopt_blocks() {
    let policy = TierEligibilityPolicy {
        max_deopt_rate_millionths: 0,
        ..default_policy()
    };
    let mut p = TierProfile::new("pz1", "fn_zero_deopt_rate");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 500;
    p.deopt_count = 1;
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
}

#[test]
fn policy_zero_max_lifetime_deopts_any_deopt_blocks() {
    let policy = TierEligibilityPolicy {
        max_lifetime_deopts: 0,
        ..default_policy()
    };
    let mut p = TierProfile::new("pz2", "fn_zero_lifetime");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = 500;
    p.deopt_count = 1;
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
}

#[test]
fn policy_max_invocations_u64_max() {
    let policy = TierEligibilityPolicy {
        min_invocations: u64::MAX,
        ..default_policy()
    };
    let mut p = TierProfile::new("pz3", "fn_max_inv");
    p.current_tier = ExecutionTier::Interpreted;
    p.invocation_count = u64::MAX - 1;
    p.rehash();
    let v = evaluate_eligibility(&p, &policy);
    assert!(!v.eligible);
}

// =========================================================================
// Report aggregation
// =========================================================================

#[test]
fn report_empty_profiles() {
    let policy = default_policy();
    let epoch = SecurityEpoch::from_raw(1);
    let report = build_eligibility_report(&[], &policy, &epoch);
    assert_eq!(report.total_functions, 0);
    assert_eq!(report.eligible_count, 0);
    assert_eq!(report.deopt_rate_millionths, 0);
}

#[test]
fn report_all_eligible() {
    let policy = default_policy();
    let epoch = SecurityEpoch::from_raw(1);
    let profiles: Vec<TierProfile> = (0..5).map(|_| warm_baseline_profile(500, 5)).collect();
    let report = build_eligibility_report(&profiles, &policy, &epoch);
    assert_eq!(report.total_functions, 5);
    assert_eq!(report.eligible_count, 5);
    assert_eq!(report.deopt_rate_millionths, 0);
}

#[test]
fn report_mixed_eligibility() {
    let policy = default_policy();
    let epoch = SecurityEpoch::from_raw(1);
    let eligible = warm_baseline_profile(500, 5);
    let mut ineligible = TierProfile::new("inel", "fn_cold");
    ineligible.current_tier = ExecutionTier::Interpreted;
    ineligible.invocation_count = 5; // too low
    ineligible.rehash();
    let report = build_eligibility_report(&[eligible, ineligible], &policy, &epoch);
    assert_eq!(report.total_functions, 2);
    assert_eq!(report.eligible_count, 1);
    assert_eq!(report.verdicts.len(), 2);
}

#[test]
fn report_aggregate_deopt_rate() {
    let policy = default_policy();
    let epoch = SecurityEpoch::from_raw(1);
    let mut p1 = TierProfile::new("agg1", "fn_a");
    p1.invocation_count = 1000;
    p1.deopt_count = 10;
    p1.rehash();
    let mut p2 = TierProfile::new("agg2", "fn_b");
    p2.invocation_count = 1000;
    p2.deopt_count = 0;
    p2.rehash();
    let report = build_eligibility_report(&[p1, p2], &policy, &epoch);
    // Aggregate: 10 deopts / 2000 invocations = 5000 (0.5%)
    assert_eq!(report.deopt_rate_millionths, 5000);
}

#[test]
fn report_deterministic_across_calls() {
    let policy = default_policy();
    let epoch = SecurityEpoch::from_raw(1);
    let profiles = vec![warm_baseline_profile(500, 3)];
    let r1 = build_eligibility_report(&profiles, &policy, &epoch);
    let r2 = build_eligibility_report(&profiles, &policy, &epoch);
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.eligible_count, r2.eligible_count);
    assert_eq!(r1.deopt_rate_millionths, r2.deopt_rate_millionths);
}

#[test]
fn report_id_contains_epoch() {
    let epoch = SecurityEpoch::from_raw(42);
    let report = build_eligibility_report(&[], &default_policy(), &epoch);
    assert!(report.report_id.contains("42"));
}

// =========================================================================
// record_deopt and add_probe
// =========================================================================

#[test]
fn record_deopt_sets_tier_to_deoptimized() {
    let mut p = TierProfile::new("rd0", "fn_deopt");
    p.current_tier = ExecutionTier::Optimized;
    p.invocation_count = 1000;
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "site_0",
        &SecurityEpoch::from_raw(10),
    );
    assert_eq!(p.current_tier, ExecutionTier::Deoptimized);
    assert_eq!(p.deopt_count, 1);
    assert_eq!(p.deopt_events.len(), 1);
    assert_eq!(p.last_transition_epoch, SecurityEpoch::from_raw(10));
}

#[test]
fn record_deopt_increments_counter() {
    let mut p = TierProfile::new("rd1", "fn_multi_deopt");
    p.current_tier = ExecutionTier::Optimized;
    for i in 0..5 {
        p.current_tier = ExecutionTier::Optimized; // manually reset tier
        record_deopt(
            &mut p,
            DeoptReason::BoundsCheck,
            &format!("site_{i}"),
            &SecurityEpoch::from_raw(i),
        );
    }
    assert_eq!(p.deopt_count, 5);
    assert_eq!(p.deopt_events.len(), 5);
    // Counters should be monotonically increasing
    for (idx, evt) in p.deopt_events.iter().enumerate() {
        assert_eq!(evt.counter, (idx + 1) as u64);
    }
}

#[test]
fn record_deopt_preserves_source_tier() {
    let mut p = TierProfile::new("rd2", "fn_source_tier");
    p.current_tier = ExecutionTier::Specialized;
    record_deopt(
        &mut p,
        DeoptReason::UnstableInlineCache,
        "s0",
        &SecurityEpoch::from_raw(1),
    );
    assert_eq!(p.deopt_events[0].source_tier, ExecutionTier::Specialized);
}

#[test]
fn add_probe_generates_unique_ids() {
    let mut p = TierProfile::new("ap0", "fn_probes");
    add_probe(&mut p, ProbeKind::TypeProfile, "s0", 10, 100);
    add_probe(&mut p, ProbeKind::TypeProfile, "s0", 20, 200);
    add_probe(&mut p, ProbeKind::BranchCoverage, "s1", 30, 300);
    assert_eq!(p.probes.len(), 3);
    // All probe IDs should be unique
    let mut ids: Vec<&str> = p.probes.iter().map(|pr| pr.probe_id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 3);
}

#[test]
fn add_probe_rehashes() {
    let mut p = TierProfile::new("ap1", "fn_rehash");
    let hash_before = p.content_hash;
    add_probe(&mut p, ProbeKind::TypeProfile, "s0", 10, 100);
    assert_ne!(hash_before, p.content_hash);
}

// =========================================================================
// TierProfile and content hashing
// =========================================================================

#[test]
fn profile_new_starts_interpreted() {
    let p = TierProfile::new("ph0", "fn_new");
    assert_eq!(p.current_tier, ExecutionTier::Interpreted);
    assert_eq!(p.invocation_count, 0);
    assert_eq!(p.deopt_count, 0);
    assert!(p.probes.is_empty());
    assert!(p.deopt_events.is_empty());
}

#[test]
fn profile_hash_deterministic() {
    let p1 = TierProfile::new("ph1", "fn_det");
    let p2 = TierProfile::new("ph1", "fn_det");
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn profile_hash_changes_on_invocation_count() {
    let mut p1 = TierProfile::new("ph2", "fn_inv");
    let mut p2 = TierProfile::new("ph2", "fn_inv");
    p1.invocation_count = 100;
    p1.rehash();
    p2.invocation_count = 101;
    p2.rehash();
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn profile_hash_changes_on_tier() {
    let mut p1 = TierProfile::new("ph3", "fn_tier");
    let mut p2 = TierProfile::new("ph3", "fn_tier");
    p1.current_tier = ExecutionTier::Baseline;
    p1.rehash();
    p2.current_tier = ExecutionTier::Optimized;
    p2.rehash();
    assert_ne!(p1.content_hash, p2.content_hash);
}

// =========================================================================
// Serde roundtrips for all types
// =========================================================================

#[test]
fn policy_serde_roundtrip() {
    let policy = default_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let back: TierEligibilityPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn profile_serde_roundtrip_with_probes_and_events() {
    let mut p = TierProfile::new("serde0", "fn_serde");
    p.current_tier = ExecutionTier::Baseline;
    p.invocation_count = 500;
    add_probe(&mut p, ProbeKind::TypeProfile, "s0", 100, 900_000);
    record_deopt(
        &mut p,
        DeoptReason::TypeMismatch,
        "s1",
        &SecurityEpoch::from_raw(5),
    );
    let json = serde_json::to_string(&p).unwrap();
    let back: TierProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p.profile_id, back.profile_id);
    assert_eq!(p.deopt_count, back.deopt_count);
    assert_eq!(p.probes.len(), back.probes.len());
    assert_eq!(p.deopt_events.len(), back.deopt_events.len());
    assert_eq!(p.content_hash, back.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let policy = default_policy();
    let epoch = SecurityEpoch::from_raw(1);
    let profiles = vec![warm_baseline_profile(500, 3)];
    let report = build_eligibility_report(&profiles, &policy, &epoch);
    let json = serde_json::to_string(&report).unwrap();
    let back = serde_json::from_str::<
        frankenengine_engine::tier_eligibility_substrate::TierEligibilityReport,
    >(&json)
    .unwrap();
    assert_eq!(report.total_functions, back.total_functions);
    assert_eq!(report.eligible_count, back.eligible_count);
    assert_eq!(report.content_hash, back.content_hash);
}

// =========================================================================
// Manifest
// =========================================================================

#[test]
fn manifest_is_empty_and_deterministic() {
    let m1 = franken_engine_tier_eligibility_manifest();
    let m2 = franken_engine_tier_eligibility_manifest();
    assert_eq!(m1.total_functions, 0);
    assert_eq!(m1.eligible_count, 0);
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn manifest_report_id_contains_bead_and_schema() {
    let m = franken_engine_tier_eligibility_manifest();
    assert!(m.report_id.contains(TIER_ELIGIBILITY_BEAD_ID));
    assert!(m.report_id.contains(TIER_ELIGIBILITY_SCHEMA_VERSION));
}

// =========================================================================
// Tier rank and enum coverage
// =========================================================================

#[test]
fn tier_rank_deoptimized_is_zero() {
    assert_eq!(tier_rank(ExecutionTier::Deoptimized), 0);
}

#[test]
fn tier_rank_specialized_is_four() {
    assert_eq!(tier_rank(ExecutionTier::Specialized), 4);
}

#[test]
fn all_deopt_reasons_display_non_empty() {
    let reasons = [
        DeoptReason::TypeMismatch,
        DeoptReason::MapTransition,
        DeoptReason::OverflowCheck,
        DeoptReason::BoundsCheck,
        DeoptReason::UnstableInlineCache,
        DeoptReason::MissingFeedback,
        DeoptReason::PolicyRejection,
    ];
    for r in &reasons {
        let s = format!("{r}");
        assert!(!s.is_empty());
    }
}

#[test]
fn all_probe_kinds_display_non_empty() {
    let kinds = [
        ProbeKind::TypeProfile,
        ProbeKind::AllocationSite,
        ProbeKind::BranchCoverage,
        ProbeKind::CallFrequency,
        ProbeKind::InlineCacheState,
    ];
    for k in &kinds {
        let s = format!("{k}");
        assert!(!s.is_empty());
    }
}

#[test]
fn all_deopt_reasons_serde_roundtrip() {
    let reasons = [
        DeoptReason::TypeMismatch,
        DeoptReason::MapTransition,
        DeoptReason::OverflowCheck,
        DeoptReason::BoundsCheck,
        DeoptReason::UnstableInlineCache,
        DeoptReason::MissingFeedback,
        DeoptReason::PolicyRejection,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: DeoptReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// =========================================================================
// Constants stability
// =========================================================================

#[test]
fn constants_stable() {
    assert_eq!(COMPONENT, "tier_eligibility_substrate");
    assert_eq!(TIER_ELIGIBILITY_BEAD_ID, "bd-1lsy.4.11.2");
    assert_eq!(TIER_ELIGIBILITY_POLICY_ID, "RGC-310B");
    assert!(TIER_ELIGIBILITY_SCHEMA_VERSION.starts_with("franken-engine."));
}
