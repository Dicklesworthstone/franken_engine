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

//! Integration tests for the `tier_eligibility_substrate` module.
//!
//! Covers constants, enum Display/serde, struct construction, eligibility
//! evaluation, deopt rate computation, feedback stability, cooldown,
//! report building, manifest generation, and content-hash determinism.

use std::collections::BTreeSet;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tier_eligibility_substrate::{
    COMPONENT, DeoptEvent, DeoptReason, ExecutionTier, ProbeKind, ProbeRecord,
    TIER_ELIGIBILITY_BEAD_ID, TIER_ELIGIBILITY_POLICY_ID, TIER_ELIGIBILITY_SCHEMA_VERSION,
    TierEligibilityPolicy, TierEligibilityReport, TierEligibilityVerdict, TierProfile,
    TierTransitionReason, add_probe, build_eligibility_report, compute_deopt_rate, cooldown_active,
    evaluate_eligibility, franken_engine_tier_eligibility_manifest, is_feedback_stable,
    record_deopt, tier_rank,
};

// =========================================================================
// 1. Constants
// =========================================================================

#[test]
fn constant_schema_version_is_nonempty_and_versioned() {
    assert!(!TIER_ELIGIBILITY_SCHEMA_VERSION.is_empty());
    assert!(
        TIER_ELIGIBILITY_SCHEMA_VERSION.contains(".v"),
        "schema version should contain a version suffix"
    );
}

#[test]
fn constant_bead_id_starts_with_bd() {
    assert!(TIER_ELIGIBILITY_BEAD_ID.starts_with("bd-"));
}

#[test]
fn constant_policy_id_starts_with_rgc() {
    assert!(TIER_ELIGIBILITY_POLICY_ID.starts_with("RGC-"));
}

#[test]
fn constant_component_matches_module_name() {
    assert_eq!(COMPONENT, "tier_eligibility_substrate");
}

// =========================================================================
// 2. ExecutionTier
// =========================================================================

#[test]
fn execution_tier_display_all_variants_unique() {
    let tiers = [
        ExecutionTier::Interpreted,
        ExecutionTier::Baseline,
        ExecutionTier::Optimized,
        ExecutionTier::Specialized,
        ExecutionTier::Deoptimized,
    ];
    let mut seen = BTreeSet::new();
    for t in &tiers {
        let s = t.to_string();
        assert!(!s.is_empty());
        seen.insert(s);
    }
    assert_eq!(
        seen.len(),
        5,
        "all ExecutionTier display strings must be unique"
    );
}

#[test]
fn execution_tier_rank_strict_ordering() {
    assert!(tier_rank(ExecutionTier::Deoptimized) < tier_rank(ExecutionTier::Interpreted));
    assert!(tier_rank(ExecutionTier::Interpreted) < tier_rank(ExecutionTier::Baseline));
    assert!(tier_rank(ExecutionTier::Baseline) < tier_rank(ExecutionTier::Optimized));
    assert!(tier_rank(ExecutionTier::Optimized) < tier_rank(ExecutionTier::Specialized));
}

#[test]
fn execution_tier_serde_roundtrip_all_variants() {
    for tier in [
        ExecutionTier::Interpreted,
        ExecutionTier::Baseline,
        ExecutionTier::Optimized,
        ExecutionTier::Specialized,
        ExecutionTier::Deoptimized,
    ] {
        let json = serde_json::to_string(&tier).expect("serialize");
        let restored: ExecutionTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tier, restored);
    }
}

#[test]
fn execution_tier_rank_values_are_distinct() {
    let ranks: Vec<u32> = [
        ExecutionTier::Deoptimized,
        ExecutionTier::Interpreted,
        ExecutionTier::Baseline,
        ExecutionTier::Optimized,
        ExecutionTier::Specialized,
    ]
    .iter()
    .map(|t| tier_rank(*t))
    .collect();
    let unique: BTreeSet<u32> = ranks.iter().copied().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn execution_tier_deoptimized_has_lowest_rank() {
    assert_eq!(tier_rank(ExecutionTier::Deoptimized), 0);
}

// =========================================================================
// 3. TierTransitionReason
// =========================================================================

#[test]
fn transition_reason_display_all_variants_unique() {
    let reasons = [
        TierTransitionReason::HotLoopDetected,
        TierTransitionReason::ProfileThresholdReached,
        TierTransitionReason::InlineCacheMonomorphic,
        TierTransitionReason::TypeFeedbackStable,
        TierTransitionReason::DeoptBailout,
        TierTransitionReason::PolicyOverride,
        TierTransitionReason::ManualProbe,
    ];
    let mut seen = BTreeSet::new();
    for r in &reasons {
        seen.insert(r.to_string());
    }
    assert_eq!(seen.len(), 7);
}

#[test]
fn transition_reason_serde_roundtrip_all_variants() {
    for reason in [
        TierTransitionReason::HotLoopDetected,
        TierTransitionReason::ProfileThresholdReached,
        TierTransitionReason::InlineCacheMonomorphic,
        TierTransitionReason::TypeFeedbackStable,
        TierTransitionReason::DeoptBailout,
        TierTransitionReason::PolicyOverride,
        TierTransitionReason::ManualProbe,
    ] {
        let json = serde_json::to_string(&reason).expect("serialize");
        let restored: TierTransitionReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, restored);
    }
}

#[test]
fn transition_reason_debug_contains_variant_name() {
    let reason = TierTransitionReason::HotLoopDetected;
    let dbg = format!("{reason:?}");
    assert!(dbg.contains("HotLoopDetected"));
}

// =========================================================================
// 4. DeoptReason
// =========================================================================

#[test]
fn deopt_reason_display_all_variants_unique() {
    let reasons = [
        DeoptReason::TypeMismatch,
        DeoptReason::MapTransition,
        DeoptReason::OverflowCheck,
        DeoptReason::BoundsCheck,
        DeoptReason::UnstableInlineCache,
        DeoptReason::MissingFeedback,
        DeoptReason::PolicyRejection,
    ];
    let mut seen = BTreeSet::new();
    for r in &reasons {
        seen.insert(r.to_string());
    }
    assert_eq!(seen.len(), 7);
}

#[test]
fn deopt_reason_serde_roundtrip_all_variants() {
    for reason in [
        DeoptReason::TypeMismatch,
        DeoptReason::MapTransition,
        DeoptReason::OverflowCheck,
        DeoptReason::BoundsCheck,
        DeoptReason::UnstableInlineCache,
        DeoptReason::MissingFeedback,
        DeoptReason::PolicyRejection,
    ] {
        let json = serde_json::to_string(&reason).expect("serialize");
        let restored: DeoptReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, restored);
    }
}

#[test]
fn deopt_reason_display_specific_strings() {
    assert_eq!(DeoptReason::TypeMismatch.to_string(), "type_mismatch");
    assert_eq!(DeoptReason::BoundsCheck.to_string(), "bounds_check");
    assert_eq!(DeoptReason::PolicyRejection.to_string(), "policy_rejection");
}

// =========================================================================
// 5. ProbeKind
// =========================================================================

#[test]
fn probe_kind_display_all_variants_unique() {
    let kinds = [
        ProbeKind::TypeProfile,
        ProbeKind::AllocationSite,
        ProbeKind::BranchCoverage,
        ProbeKind::CallFrequency,
        ProbeKind::InlineCacheState,
    ];
    let mut seen = BTreeSet::new();
    for k in &kinds {
        seen.insert(k.to_string());
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn probe_kind_serde_roundtrip_all_variants() {
    for kind in [
        ProbeKind::TypeProfile,
        ProbeKind::AllocationSite,
        ProbeKind::BranchCoverage,
        ProbeKind::CallFrequency,
        ProbeKind::InlineCacheState,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let restored: ProbeKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, restored);
    }
}

#[test]
fn probe_kind_display_specific_strings() {
    assert_eq!(ProbeKind::TypeProfile.to_string(), "type_profile");
    assert_eq!(
        ProbeKind::InlineCacheState.to_string(),
        "inline_cache_state"
    );
}

// =========================================================================
// 6. TierProfile
// =========================================================================

#[test]
fn tier_profile_new_starts_interpreted_with_zero_counts() {
    let profile = TierProfile::new("prof-1", "my_func");
    assert_eq!(profile.profile_id, "prof-1");
    assert_eq!(profile.function_id, "my_func");
    assert_eq!(profile.current_tier, ExecutionTier::Interpreted);
    assert_eq!(profile.invocation_count, 0);
    assert_eq!(profile.deopt_count, 0);
    assert!(profile.probes.is_empty());
    assert!(profile.deopt_events.is_empty());
    assert_eq!(profile.last_transition_epoch, SecurityEpoch::GENESIS);
}

#[test]
fn tier_profile_record_deopt_transitions_to_deoptimized() {
    let mut profile = TierProfile::new("prof-rd", "fn_deopt_target");
    profile.current_tier = ExecutionTier::Optimized;
    profile.invocation_count = 200;
    profile.rehash();

    let epoch = SecurityEpoch::from_raw(7);
    record_deopt(&mut profile, DeoptReason::TypeMismatch, "bc:42", &epoch);

    assert_eq!(profile.current_tier, ExecutionTier::Deoptimized);
    assert_eq!(profile.deopt_count, 1);
    assert_eq!(profile.deopt_events.len(), 1);
    assert_eq!(profile.deopt_events[0].reason, DeoptReason::TypeMismatch);
    assert_eq!(
        profile.deopt_events[0].source_tier,
        ExecutionTier::Optimized
    );
    assert_eq!(profile.deopt_events[0].bailout_site, "bc:42");
    assert_eq!(profile.last_transition_epoch, epoch);
}

#[test]
fn tier_profile_add_probe_appends_and_rehashes() {
    let mut profile = TierProfile::new("prof-ap", "fn_probed");
    let hash_before = profile.content_hash;

    add_probe(
        &mut profile,
        ProbeKind::CallFrequency,
        "site-0",
        50,
        750_000,
    );

    assert_eq!(profile.probes.len(), 1);
    assert_eq!(profile.probes[0].kind, ProbeKind::CallFrequency);
    assert_eq!(profile.probes[0].sample_count, 50);
    assert_eq!(profile.probes[0].value_millionths, 750_000);
    assert_ne!(profile.content_hash, hash_before);
}

#[test]
fn tier_profile_rehash_deterministic() {
    let mut a = TierProfile::new("det-1", "fn_det");
    a.invocation_count = 100;
    add_probe(&mut a, ProbeKind::TypeProfile, "s0", 20, 900_000);
    a.rehash();

    let mut b = TierProfile::new("det-1", "fn_det");
    b.invocation_count = 100;
    add_probe(&mut b, ProbeKind::TypeProfile, "s0", 20, 900_000);
    b.rehash();

    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn tier_profile_content_hash_changes_on_mutation() {
    let mut profile = TierProfile::new("mut-1", "fn_mut");
    let h1 = profile.content_hash;
    profile.invocation_count = 999;
    profile.rehash();
    assert_ne!(profile.content_hash, h1);
}

// =========================================================================
// 7. TierEligibilityPolicy
// =========================================================================

#[test]
fn policy_default_has_sensible_values() {
    let policy = TierEligibilityPolicy::default();
    assert!(policy.min_invocations > 0);
    assert!(policy.min_feedback_stability_millionths <= 1_000_000);
    assert!(policy.deopt_cooldown_epochs > 0);
    assert!(policy.max_deopt_rate_millionths <= 1_000_000);
    assert!(policy.min_probe_samples > 0);
    assert!(policy.max_lifetime_deopts > 0);
    assert!(policy.min_confidence_millionths <= 1_000_000);
    assert!(!policy.policy_id.is_empty());
}

#[test]
fn policy_content_hash_deterministic() {
    let a = TierEligibilityPolicy::default().content_hash();
    let b = TierEligibilityPolicy::default().content_hash();
    assert_eq!(a, b);
}

#[test]
fn policy_serde_roundtrip() {
    let policy = TierEligibilityPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let restored: TierEligibilityPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, restored);
}

// =========================================================================
// 8. evaluate_eligibility
// =========================================================================

/// Helper: create a profile at a given tier with the specified invocation count
/// and optional stable probes.
fn make_profile(
    id: &str,
    function_id: &str,
    tier: ExecutionTier,
    invocation_count: u64,
    stable_probes: usize,
) -> TierProfile {
    let mut profile = TierProfile::new(id, function_id);
    profile.current_tier = tier;
    profile.invocation_count = invocation_count;
    for i in 0..stable_probes {
        add_probe(
            &mut profile,
            ProbeKind::TypeProfile,
            &format!("site-{i}"),
            100,
            900_000,
        );
    }
    profile.rehash();
    profile
}

#[test]
fn evaluate_eligible_baseline_to_optimized() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile("e-b2o", "fn_hot", ExecutionTier::Baseline, 500, 5);

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(verdict.eligible);
    assert_eq!(verdict.target_tier, ExecutionTier::Optimized);
    assert!(!verdict.reasons.is_empty());
    assert!(verdict.confidence_millionths > 0);
}

#[test]
fn evaluate_not_eligible_low_invocations() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile("e-low", "fn_cold", ExecutionTier::Interpreted, 5, 0);

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert!(verdict.probe_summary.contains("invocations"));
}

#[test]
fn evaluate_not_eligible_unstable_feedback_for_optimized() {
    let policy = TierEligibilityPolicy::default();
    // Baseline -> Optimized requires stable feedback. Use probes with
    // very low sample counts so stability is insufficient.
    let mut profile = TierProfile::new("e-unstable", "fn_unstable");
    profile.current_tier = ExecutionTier::Baseline;
    profile.invocation_count = 500;
    // Add probes that all have fewer than 10 samples (the hardcoded threshold).
    for i in 0..5 {
        add_probe(
            &mut profile,
            ProbeKind::TypeProfile,
            &format!("site-{i}"),
            3,
            900_000,
        );
    }
    profile.rehash();

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert!(verdict.probe_summary.contains("feedback"));
}

#[test]
fn evaluate_deopt_cooldown_blocks() {
    let policy = TierEligibilityPolicy {
        deopt_cooldown_epochs: 5,
        ..TierEligibilityPolicy::default()
    };
    let mut profile = TierProfile::new("e-cd", "fn_cooldown");
    profile.current_tier = ExecutionTier::Interpreted;
    profile.invocation_count = 500;
    // Deopt at epoch 8, then set last_transition to epoch 10 (within cooldown).
    record_deopt(
        &mut profile,
        DeoptReason::MapTransition,
        "bc:7",
        &SecurityEpoch::from_raw(8),
    );
    profile.current_tier = ExecutionTier::Interpreted;
    profile.last_transition_epoch = SecurityEpoch::from_raw(10);
    profile.rehash();

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert!(verdict.probe_summary.contains("cooldown"));
}

#[test]
fn evaluate_already_specialized_is_ineligible() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile("e-spec", "fn_max", ExecutionTier::Specialized, 10_000, 10);

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert!(verdict.probe_summary.contains("highest tier"));
}

#[test]
fn evaluate_ineligible_verdict_has_zero_confidence() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile("e-zc", "fn_inelig", ExecutionTier::Interpreted, 1, 0);

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert_eq!(verdict.confidence_millionths, 0);
}

#[test]
fn evaluate_high_deopt_rate_rejects() {
    let policy = TierEligibilityPolicy::default();
    let mut profile = TierProfile::new("e-hdr", "fn_flaky");
    profile.current_tier = ExecutionTier::Interpreted;
    profile.invocation_count = 200;
    profile.deopt_count = 100; // 50% deopt rate
    profile.rehash();

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert!(verdict.probe_summary.contains("deopt_rate"));
}

#[test]
fn evaluate_interpreted_to_baseline_no_feedback_required() {
    // Interpreted -> Baseline should not require feedback stability,
    // only invocation threshold matters.
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile(
        "e-i2b",
        "fn_simple",
        ExecutionTier::Interpreted,
        500,
        0, // no probes at all
    );

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(verdict.eligible);
    assert_eq!(verdict.target_tier, ExecutionTier::Baseline);
}

#[test]
fn evaluate_eligibility_uses_policy_min_probe_samples() {
    let policy = TierEligibilityPolicy {
        min_probe_samples: 12,
        min_feedback_stability_millionths: 800_000,
        ..TierEligibilityPolicy::default()
    };
    let mut profile = make_profile(
        "e-policy-samples",
        "fn_policy_sensitive",
        ExecutionTier::Baseline,
        500,
        0,
    );
    add_probe(&mut profile, ProbeKind::TypeProfile, "s0", 12, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s1", 12, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s2", 8, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s3", 8, 900_000);
    profile.rehash();

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert!(verdict.probe_summary.contains("feedback not stable"));
}

// =========================================================================
// 9. compute_deopt_rate
// =========================================================================

#[test]
fn deopt_rate_zero_invocations_returns_zero() {
    let profile = TierProfile::new("dr-0", "fn_zero");
    assert_eq!(compute_deopt_rate(&profile), 0);
}

#[test]
fn deopt_rate_normal() {
    let mut profile = TierProfile::new("dr-norm", "fn_normal");
    profile.invocation_count = 1000;
    profile.deopt_count = 50;
    profile.rehash();
    // 50/1000 = 5% = 50_000 millionths
    assert_eq!(compute_deopt_rate(&profile), 50_000);
}

#[test]
fn deopt_rate_hundred_percent() {
    let mut profile = TierProfile::new("dr-full", "fn_full");
    profile.invocation_count = 200;
    profile.deopt_count = 200;
    profile.rehash();
    assert_eq!(compute_deopt_rate(&profile), 1_000_000);
}

// =========================================================================
// 10. is_feedback_stable
// =========================================================================

#[test]
fn feedback_stable_all_probes_sufficient() {
    let mut profile = TierProfile::new("fs-ok", "fn_stable");
    for i in 0..5 {
        add_probe(
            &mut profile,
            ProbeKind::TypeProfile,
            &format!("s{i}"),
            100,
            900_000,
        );
    }
    assert!(is_feedback_stable(&profile, 10, 800_000));
}

#[test]
fn feedback_unstable_half_insufficient() {
    let mut profile = TierProfile::new("fs-half", "fn_partial");
    add_probe(&mut profile, ProbeKind::TypeProfile, "s0", 100, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s1", 100, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s2", 3, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s3", 5, 900_000);
    // 50% stable (500_000) < 800_000 threshold
    assert!(!is_feedback_stable(&profile, 10, 800_000));
    // But passes a lower threshold
    assert!(is_feedback_stable(&profile, 10, 400_000));
}

#[test]
fn feedback_stability_respects_min_probe_samples() {
    let mut profile = TierProfile::new("fs-policy", "fn_policy_sensitive");
    add_probe(&mut profile, ProbeKind::TypeProfile, "s0", 12, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s1", 12, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s2", 8, 900_000);
    add_probe(&mut profile, ProbeKind::TypeProfile, "s3", 8, 900_000);

    assert!(is_feedback_stable(&profile, 10, 500_000));
    assert!(!is_feedback_stable(&profile, 12, 800_000));
}

#[test]
fn feedback_no_probes_not_stable() {
    let profile = TierProfile::new("fs-none", "fn_no_probes");
    assert!(!is_feedback_stable(&profile, 10, 800_000));
    // Even with zero threshold, no probes means not stable.
    assert!(!is_feedback_stable(&profile, 10, 0));
}

// =========================================================================
// 11. build_eligibility_report
// =========================================================================

#[test]
fn report_empty_profiles_produces_empty_report() {
    let policy = TierEligibilityPolicy::default();
    let epoch = SecurityEpoch::from_raw(10);
    let report = build_eligibility_report(&[], &policy, &epoch);

    assert_eq!(report.total_functions, 0);
    assert_eq!(report.eligible_count, 0);
    assert_eq!(report.deopt_rate_millionths, 0);
    assert!(report.profiles.is_empty());
    assert!(report.verdicts.is_empty());
    assert_eq!(report.epoch, epoch);
}

#[test]
fn report_mixed_results_counts_correctly() {
    let policy = TierEligibilityPolicy::default();
    let epoch = SecurityEpoch::from_raw(10);

    let eligible = make_profile("rm-e", "fn_elig", ExecutionTier::Interpreted, 500, 0);
    let ineligible = make_profile("rm-i", "fn_inelig", ExecutionTier::Interpreted, 2, 0);

    let report = build_eligibility_report(&[eligible, ineligible], &policy, &epoch);
    assert_eq!(report.total_functions, 2);
    assert_eq!(report.eligible_count, 1);
    assert_eq!(report.verdicts.len(), 2);
}

#[test]
fn report_verdict_count_matches_profile_count() {
    let policy = TierEligibilityPolicy::default();
    let epoch = SecurityEpoch::from_raw(5);

    let profiles: Vec<TierProfile> = (0..7)
        .map(|i| {
            make_profile(
                &format!("rm-{i}"),
                &format!("fn_{i}"),
                ExecutionTier::Interpreted,
                100 + i * 50,
                0,
            )
        })
        .collect();

    let report = build_eligibility_report(&profiles, &policy, &epoch);
    assert_eq!(report.total_functions, 7);
    assert_eq!(report.verdicts.len(), 7);
    assert_eq!(report.profiles.len(), 7);
}

#[test]
fn report_deterministic_for_same_inputs() {
    let policy = TierEligibilityPolicy::default();
    let epoch = SecurityEpoch::from_raw(42);

    let p1 = make_profile("rd-1", "fn_a", ExecutionTier::Interpreted, 500, 0);
    let p2 = make_profile("rd-2", "fn_b", ExecutionTier::Baseline, 300, 3);

    let report_a = build_eligibility_report(&[p1.clone(), p2.clone()], &policy, &epoch);
    let report_b = build_eligibility_report(&[p1, p2], &policy, &epoch);

    assert_eq!(report_a.content_hash, report_b.content_hash);
    assert_eq!(report_a.eligible_count, report_b.eligible_count);
    assert_eq!(
        report_a.deopt_rate_millionths,
        report_b.deopt_rate_millionths
    );
}

// =========================================================================
// 12. Manifest
// =========================================================================

#[test]
fn manifest_is_not_empty_and_has_genesis_epoch() {
    let manifest = franken_engine_tier_eligibility_manifest();
    assert_eq!(manifest.total_functions, 0);
    assert_eq!(manifest.eligible_count, 0);
    assert_eq!(manifest.epoch, SecurityEpoch::GENESIS);
    assert!(manifest.profiles.is_empty());
    assert!(manifest.verdicts.is_empty());
    assert!(!manifest.report_id.is_empty());
}

#[test]
fn manifest_deterministic() {
    let a = franken_engine_tier_eligibility_manifest();
    let b = franken_engine_tier_eligibility_manifest();
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.report_id, b.report_id);
}

// =========================================================================
// 13. Serde roundtrips (complex types)
// =========================================================================

#[test]
fn serde_roundtrip_tier_profile() {
    let mut profile = TierProfile::new("serde-p", "fn_serde");
    profile.invocation_count = 42;
    add_probe(&mut profile, ProbeKind::TypeProfile, "s0", 10, 500_000);
    record_deopt(
        &mut profile,
        DeoptReason::BoundsCheck,
        "bc:3",
        &SecurityEpoch::from_raw(1),
    );

    let json = serde_json::to_string(&profile).expect("serialize");
    let restored: TierProfile = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(profile, restored);
}

#[test]
fn serde_roundtrip_verdict() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile("sv", "fn_sv", ExecutionTier::Interpreted, 500, 0);
    let verdict = evaluate_eligibility(&profile, &policy);

    let json = serde_json::to_string(&verdict).expect("serialize");
    let restored: TierEligibilityVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(verdict, restored);
}

#[test]
fn serde_roundtrip_report() {
    let policy = TierEligibilityPolicy::default();
    let epoch = SecurityEpoch::from_raw(5);
    let profiles = vec![
        make_profile("sr-1", "fn_a", ExecutionTier::Interpreted, 500, 0),
        make_profile("sr-2", "fn_b", ExecutionTier::Baseline, 300, 3),
    ];
    let report = build_eligibility_report(&profiles, &policy, &epoch);

    let json = serde_json::to_string(&report).expect("serialize");
    let restored: TierEligibilityReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, restored);
}

// =========================================================================
// 14. Additional edge cases / coverage boosters
// =========================================================================

#[test]
fn record_deopt_multiple_events_increments_correctly() {
    let mut profile = TierProfile::new("multi-d", "fn_multi_deopt");
    profile.current_tier = ExecutionTier::Baseline;
    profile.invocation_count = 50;

    record_deopt(
        &mut profile,
        DeoptReason::TypeMismatch,
        "bc:1",
        &SecurityEpoch::from_raw(1),
    );
    record_deopt(
        &mut profile,
        DeoptReason::OverflowCheck,
        "bc:2",
        &SecurityEpoch::from_raw(2),
    );
    record_deopt(
        &mut profile,
        DeoptReason::BoundsCheck,
        "bc:3",
        &SecurityEpoch::from_raw(3),
    );

    assert_eq!(profile.deopt_count, 3);
    assert_eq!(profile.deopt_events.len(), 3);
    assert_eq!(profile.deopt_events[0].counter, 1);
    assert_eq!(profile.deopt_events[1].counter, 2);
    assert_eq!(profile.deopt_events[2].counter, 3);
}

#[test]
fn cooldown_active_no_events_always_false() {
    let profile = TierProfile::new("cd-none", "fn_clean");
    assert!(!cooldown_active(
        &profile,
        100,
        &SecurityEpoch::from_raw(1000)
    ));
}

#[test]
fn cooldown_active_within_window() {
    let mut profile = TierProfile::new("cd-in", "fn_recent");
    record_deopt(
        &mut profile,
        DeoptReason::MapTransition,
        "bc:5",
        &SecurityEpoch::from_raw(8),
    );
    // epoch 10, cooldown 5 -> 10 - 8 = 2 < 5 -> active
    assert!(cooldown_active(&profile, 5, &SecurityEpoch::from_raw(10)));
}

#[test]
fn cooldown_active_outside_window() {
    let mut profile = TierProfile::new("cd-out", "fn_old");
    record_deopt(
        &mut profile,
        DeoptReason::MapTransition,
        "bc:5",
        &SecurityEpoch::from_raw(2),
    );
    // epoch 10, cooldown 5 -> 10 - 2 = 8 >= 5 -> not active
    assert!(!cooldown_active(&profile, 5, &SecurityEpoch::from_raw(10)));
}

#[test]
fn probe_record_content_hash_deterministic() {
    let probe = ProbeRecord {
        probe_id: "probe-det".to_string(),
        kind: ProbeKind::BranchCoverage,
        site_id: "site-det".to_string(),
        sample_count: 42,
        value_millionths: 123_456,
    };
    let h1 = probe.content_hash();
    let h2 = probe.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn probe_record_display_contains_key_fields() {
    let probe = ProbeRecord {
        probe_id: "probe-disp".to_string(),
        kind: ProbeKind::CallFrequency,
        site_id: "site-disp".to_string(),
        sample_count: 42,
        value_millionths: 123_456,
    };
    let s = probe.to_string();
    assert!(s.contains("probe-disp"));
    assert!(s.contains("call_frequency"));
    assert!(s.contains("site-disp"));
}

#[test]
fn deopt_event_display_contains_reason_and_site() {
    let evt = DeoptEvent {
        event_id: "evt-disp".to_string(),
        reason: DeoptReason::OverflowCheck,
        source_tier: ExecutionTier::Optimized,
        bailout_site: "bc:99".to_string(),
        epoch: SecurityEpoch::from_raw(7),
        counter: 1,
    };
    let s = evt.to_string();
    assert!(s.contains("evt-disp"));
    assert!(s.contains("overflow_check"));
    assert!(s.contains("optimized"));
    assert!(s.contains("bc:99"));
}

#[test]
fn tier_profile_display_contains_function_id() {
    let profile = TierProfile::new("disp-prof", "fn_display_test");
    let s = profile.to_string();
    assert!(s.contains("TierProfile"));
    assert!(s.contains("fn_display_test"));
    assert!(s.contains("interpreted"));
}

#[test]
fn policy_display_contains_fields() {
    let policy = TierEligibilityPolicy::default();
    let s = policy.to_string();
    assert!(s.contains("TierEligibilityPolicy"));
    assert!(s.contains(&policy.min_invocations.to_string()));
}

#[test]
fn verdict_display_shows_eligible_flag() {
    let verdict = TierEligibilityVerdict::ineligible(ExecutionTier::Baseline, "test");
    let s = verdict.to_string();
    assert!(s.contains("eligible=false"));
    assert!(s.contains("TierEligibilityVerdict"));
}

#[test]
fn report_display_contains_counts() {
    let report = franken_engine_tier_eligibility_manifest();
    let s = report.to_string();
    assert!(s.contains("TierEligibilityReport"));
    assert!(s.contains("total=0"));
    assert!(s.contains("eligible=0"));
}

#[test]
fn report_aggregate_deopt_rate_computed_correctly() {
    let policy = TierEligibilityPolicy::default();
    let epoch = SecurityEpoch::from_raw(20);

    let mut p1 = TierProfile::new("adr-1", "fn_a");
    p1.invocation_count = 100;
    p1.deopt_count = 10;
    p1.rehash();

    let mut p2 = TierProfile::new("adr-2", "fn_b");
    p2.invocation_count = 100;
    p2.deopt_count = 0;
    p2.rehash();

    let report = build_eligibility_report(&[p1, p2], &policy, &epoch);
    // 10 deopts / 200 invocations = 5% = 50_000 millionths
    assert_eq!(report.deopt_rate_millionths, 50_000);
}

#[test]
fn evaluate_lifetime_deopts_exceeds_max_rejects() {
    let policy = TierEligibilityPolicy {
        max_lifetime_deopts: 3,
        ..TierEligibilityPolicy::default()
    };
    let mut profile = TierProfile::new("e-life", "fn_too_many");
    profile.current_tier = ExecutionTier::Interpreted;
    profile.invocation_count = 500;
    profile.deopt_count = 5; // exceeds max of 3
    profile.rehash();

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(!verdict.eligible);
    assert!(verdict.probe_summary.contains("lifetime_deopts"));
}

#[test]
fn evaluate_deoptimized_tier_targets_interpreted() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile(
        "e-deopt",
        "fn_deopt_back",
        ExecutionTier::Deoptimized,
        500,
        0,
    );

    let verdict = evaluate_eligibility(&profile, &policy);
    // Deoptimized -> Interpreted is the next tier up
    assert_eq!(verdict.target_tier, ExecutionTier::Interpreted);
}

#[test]
fn eligible_verdict_has_profile_threshold_reason() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile("e-ptr", "fn_ptr", ExecutionTier::Interpreted, 500, 0);

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(verdict.eligible);
    assert!(
        verdict
            .reasons
            .contains(&TierTransitionReason::ProfileThresholdReached)
    );
}

#[test]
fn eligible_baseline_to_optimized_has_feedback_stable_reason() {
    let policy = TierEligibilityPolicy::default();
    let profile = make_profile("e-fsr", "fn_fsr", ExecutionTier::Baseline, 500, 5);

    let verdict = evaluate_eligibility(&profile, &policy);
    assert!(verdict.eligible);
    assert!(
        verdict
            .reasons
            .contains(&TierTransitionReason::TypeFeedbackStable)
    );
    assert!(
        verdict
            .reasons
            .contains(&TierTransitionReason::ProfileThresholdReached)
    );
}

#[test]
fn ineligible_verdict_creates_via_constructor() {
    let verdict = TierEligibilityVerdict::ineligible(ExecutionTier::Optimized, "test reason");
    assert!(!verdict.eligible);
    assert_eq!(verdict.target_tier, ExecutionTier::Optimized);
    assert!(verdict.reasons.is_empty());
    assert_eq!(verdict.probe_summary, "test reason");
    // Confidence for ineligible via constructor is MILLIONTHS (1_000_000)
    assert_eq!(verdict.confidence_millionths, 1_000_000);
}

#[test]
fn report_content_hash_is_nondefault_after_build() {
    let policy = TierEligibilityPolicy::default();
    let epoch = SecurityEpoch::from_raw(1);
    let report = build_eligibility_report(&[], &policy, &epoch);
    // After rehash, content_hash should not be all zeros.
    assert_ne!(report.content_hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn report_id_contains_epoch() {
    let epoch = SecurityEpoch::from_raw(99);
    let policy = TierEligibilityPolicy::default();
    let report = build_eligibility_report(&[], &policy, &epoch);
    assert!(report.report_id.contains("99"));
}

#[test]
fn multiple_add_probe_creates_distinct_ids() {
    let mut profile = TierProfile::new("mp", "fn_multi_probe");
    add_probe(&mut profile, ProbeKind::TypeProfile, "s0", 10, 100_000);
    add_probe(&mut profile, ProbeKind::BranchCoverage, "s1", 20, 200_000);
    add_probe(&mut profile, ProbeKind::CallFrequency, "s2", 30, 300_000);

    assert_eq!(profile.probes.len(), 3);
    let ids: BTreeSet<&str> = profile.probes.iter().map(|p| p.probe_id.as_str()).collect();
    assert_eq!(ids.len(), 3, "all probe IDs must be unique");
}

#[test]
fn deopt_event_id_contains_function_id() {
    let mut profile = TierProfile::new("eid", "fn_event_id_check");
    profile.current_tier = ExecutionTier::Optimized;
    record_deopt(
        &mut profile,
        DeoptReason::UnstableInlineCache,
        "bc:55",
        &SecurityEpoch::from_raw(3),
    );
    assert!(
        profile.deopt_events[0]
            .event_id
            .contains("fn_event_id_check")
    );
}
