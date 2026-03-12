//! Integration tests for `polymorphic_inline_cache` module.
//!
//! Bead: bd-1lsy.7.6.2 [RGC-606B]
//!
//! Covers all 8 specimen families:
//!   - MonomorphicFastPath
//!   - PolymorphicInBounds
//!   - MegamorphicTransition
//!   - GuardFailure
//!   - ColdEntryPruning
//!   - DeterministicReplay
//!   - BailoutDecisionLogic
//!   - ScopeAggregation

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

use frankenengine_engine::polymorphic_inline_cache::{
    BEAD_ID, BailoutDecision, BailoutVerdict, COMPONENT, DEFAULT_COLD_PRUNE_THRESHOLD,
    DEFAULT_MAX_POLY_ENTRIES, DEFAULT_MEGAMORPHIC_THRESHOLD, DEFAULT_MIN_ACCESS_COUNT,
    DEFAULT_MIN_WARM_HIT_RATE, IcPolicyConfig, IcReplayLog, IcScopeProfile, IcSiteKind,
    IcSiteProfile, IcSiteState, PIC_DECISION_SCHEMA_VERSION, PIC_PROFILE_SCHEMA_VERSION,
    PIC_REPLAY_SCHEMA_VERSION, PIC_SCHEMA_VERSION, PicEvidenceInventory, PicExpectedOutcome,
    PicSpecimenFamily, PicSpecimenResult, PicVerdict, decide_bailout,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// =========================================================================
// Constants & schema version checks
// =========================================================================

#[test]
fn constants_are_well_formed() {
    assert_eq!(COMPONENT, "polymorphic_inline_cache");
    assert_eq!(BEAD_ID, "bd-1lsy.7.6.2");
    assert!(PIC_SCHEMA_VERSION.starts_with("frankenengine."));
    assert!(PIC_PROFILE_SCHEMA_VERSION.starts_with("frankenengine."));
    assert!(PIC_DECISION_SCHEMA_VERSION.starts_with("frankenengine."));
    assert!(PIC_REPLAY_SCHEMA_VERSION.starts_with("frankenengine."));
}

#[test]
fn default_thresholds_are_reasonable() {
    assert!(DEFAULT_MAX_POLY_ENTRIES >= 2);
    assert!(DEFAULT_MIN_WARM_HIT_RATE > 0);
    assert!(DEFAULT_MIN_WARM_HIT_RATE <= 1_000_000);
    assert!(DEFAULT_MIN_ACCESS_COUNT > 0);
    assert!(DEFAULT_MEGAMORPHIC_THRESHOLD > DEFAULT_MAX_POLY_ENTRIES as u32);
    assert!(DEFAULT_COLD_PRUNE_THRESHOLD > 0);
    assert!(DEFAULT_COLD_PRUNE_THRESHOLD < 1_000_000);
}

// =========================================================================
// IcSiteKind
// =========================================================================

#[test]
fn ic_site_kind_all_exhaustive() {
    assert_eq!(IcSiteKind::ALL.len(), 8);
    for kind in IcSiteKind::ALL {
        let display = format!("{kind}");
        assert!(!display.is_empty());
    }
}

#[test]
fn ic_site_kind_monomorphic_benefit() {
    assert!(IcSiteKind::PropertyLoad.benefits_from_monomorphic());
    assert!(IcSiteKind::PropertyStore.benefits_from_monomorphic());
    assert!(IcSiteKind::CallSite.benefits_from_monomorphic());
    assert!(IcSiteKind::ConstructorSite.benefits_from_monomorphic());
    assert!(!IcSiteKind::ComputedLoad.benefits_from_monomorphic());
    assert!(!IcSiteKind::ComputedStore.benefits_from_monomorphic());
    assert!(!IcSiteKind::InOperator.benefits_from_monomorphic());
    assert!(!IcSiteKind::InstanceOf.benefits_from_monomorphic());
}

#[test]
fn ic_site_kind_display_round_trips_through_serde() {
    for kind in IcSiteKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: IcSiteKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn ic_site_kind_ordering_is_deterministic() {
    let mut kinds: Vec<IcSiteKind> = IcSiteKind::ALL.to_vec();
    let original = kinds.clone();
    kinds.sort();
    assert_eq!(kinds, original, "ALL should already be in derived order");
}

// =========================================================================
// IcSiteState
// =========================================================================

#[test]
fn ic_site_state_all_exhaustive() {
    assert_eq!(IcSiteState::ALL.len(), 4);
}

#[test]
fn ic_site_state_display() {
    assert_eq!(format!("{}", IcSiteState::Uninitialised), "uninitialised");
    assert_eq!(format!("{}", IcSiteState::Monomorphic), "monomorphic");
    assert_eq!(format!("{}", IcSiteState::Polymorphic), "polymorphic");
    assert_eq!(format!("{}", IcSiteState::Megamorphic), "megamorphic");
}

#[test]
fn ic_site_state_ordering_reflects_degradation() {
    assert!(IcSiteState::Uninitialised < IcSiteState::Monomorphic);
    assert!(IcSiteState::Monomorphic < IcSiteState::Polymorphic);
    assert!(IcSiteState::Polymorphic < IcSiteState::Megamorphic);
}

#[test]
fn ic_site_state_serde_round_trip() {
    for state in IcSiteState::ALL {
        let json = serde_json::to_string(state).unwrap();
        let back: IcSiteState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

// =========================================================================
// IcSiteProfile — MonomorphicFastPath family
// =========================================================================

#[test]
fn monomorphic_single_shape_stays_mono() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_main");
    assert_eq!(profile.current_state, IcSiteState::Uninitialised);
    assert_eq!(profile.total_accesses, 0);

    let changed = profile.record_access(42);
    assert!(changed, "uninitialised → mono should be a transition");
    assert_eq!(profile.current_state, IcSiteState::Monomorphic);
    assert_eq!(profile.observed_shapes, vec![42]);

    // Same shape repeated: state should not change.
    for _ in 0..200 {
        let c = profile.record_access(42);
        assert!(!c);
    }
    assert_eq!(profile.current_state, IcSiteState::Monomorphic);
    assert!(profile.is_monomorphic());
    assert!(!profile.is_megamorphic());
    assert!(profile.is_warm());
    assert_eq!(profile.transition_count, 1); // only the initial uninit→mono
}

#[test]
fn monomorphic_hit_rate_near_perfect() {
    let mut profile = IcSiteProfile::new(10, IcSiteKind::CallSite, "fn_foo");
    profile.record_access(1);
    for _ in 0..199 {
        profile.record_access(1);
    }
    let rate = profile.hit_rate_millionths();
    // 1 transition (uninit→mono) out of 200 accesses → 199/200 = 995_000
    assert!(rate > 990_000, "expected near-perfect hit rate, got {rate}");
}

#[test]
fn monomorphic_hash_is_stable() {
    let mut p1 = IcSiteProfile::new(5, IcSiteKind::PropertyStore, "scope_a");
    let mut p2 = IcSiteProfile::new(5, IcSiteKind::PropertyStore, "scope_a");
    p1.record_access(100);
    p2.record_access(100);
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn monomorphic_different_offsets_different_hashes() {
    let mut p1 = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "s");
    let mut p2 = IcSiteProfile::new(1, IcSiteKind::PropertyLoad, "s");
    p1.record_access(1);
    p2.record_access(1);
    assert_ne!(p1.content_hash, p2.content_hash);
}

// =========================================================================
// IcSiteProfile — PolymorphicInBounds family
// =========================================================================

#[test]
fn polymorphic_two_shapes() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_poly");
    profile.record_access(1);
    assert_eq!(profile.current_state, IcSiteState::Monomorphic);

    let changed = profile.record_access(2);
    assert!(changed, "mono → poly should be a transition");
    assert_eq!(profile.current_state, IcSiteState::Polymorphic);
    assert_eq!(profile.observed_shapes.len(), 2);
    assert_eq!(profile.transition_count, 2); // uninit→mono, mono→poly
}

#[test]
fn polymorphic_max_shapes_still_poly() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::ComputedLoad, "fn_max_poly");
    for shape_id in 1..=(DEFAULT_MAX_POLY_ENTRIES as u64) {
        profile.record_access(shape_id);
    }
    assert_eq!(profile.current_state, IcSiteState::Polymorphic);
    assert_eq!(profile.observed_shapes.len(), DEFAULT_MAX_POLY_ENTRIES);
}

#[test]
fn polymorphic_shapes_are_sorted() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_sort");
    profile.record_access(99);
    profile.record_access(3);
    profile.record_access(50);
    let shapes = &profile.observed_shapes;
    assert_eq!(shapes, &[3, 50, 99]);
}

#[test]
fn polymorphic_duplicate_shape_no_transition() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_dup");
    profile.record_access(1);
    profile.record_access(2);
    let tc = profile.transition_count;
    let changed = profile.record_access(2); // duplicate
    assert!(!changed);
    assert_eq!(profile.transition_count, tc);
}

// =========================================================================
// IcSiteProfile — MegamorphicTransition family
// =========================================================================

#[test]
fn megamorphic_transition_at_threshold() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_mega");
    for shape_id in 1..=(DEFAULT_MAX_POLY_ENTRIES as u64 + 1) {
        profile.record_access(shape_id);
    }
    assert_eq!(profile.current_state, IcSiteState::Megamorphic);
    assert!(profile.is_megamorphic());
    assert!(profile.megamorphic_sticky);
}

#[test]
fn megamorphic_sticky_prevents_demotion() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_sticky");
    // Drive to megamorphic
    for shape_id in 1..=(DEFAULT_MAX_POLY_ENTRIES as u64 + 1) {
        profile.record_access(shape_id);
    }
    assert_eq!(profile.current_state, IcSiteState::Megamorphic);

    // Even after many accesses of the same shape, should stay mega
    for _ in 0..100 {
        let changed = profile.record_access(1);
        assert!(!changed);
    }
    assert_eq!(profile.current_state, IcSiteState::Megamorphic);
}

#[test]
fn megamorphic_many_shapes_count_preserved() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::ComputedStore, "fn_many");
    for shape_id in 1..=20u64 {
        profile.record_access(shape_id);
    }
    assert_eq!(profile.observed_shapes.len(), 20);
    assert!(profile.is_megamorphic());
}

// =========================================================================
// IcSiteProfile — GuardFailure family
// =========================================================================

#[test]
fn guard_failure_increments() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_gf");
    profile.record_access(1);
    assert_eq!(profile.guard_failure_count, 0);

    profile.record_guard_failure();
    assert_eq!(profile.guard_failure_count, 1);
    profile.record_guard_failure();
    assert_eq!(profile.guard_failure_count, 2);
}

#[test]
fn guard_failure_affects_hit_rate() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_gf_rate");
    profile.record_access(1);
    for _ in 0..99 {
        profile.record_access(1);
    }
    let rate_before = profile.hit_rate_millionths();

    for _ in 0..50 {
        profile.record_guard_failure();
    }
    // Guard failures don't add accesses, so we need more accesses to
    // see the effect since hit_rate = (accesses - transitions - failures) / accesses.
    // But the failures are already counted relative to current total_accesses.
    let rate_after = profile.hit_rate_millionths();
    assert!(
        rate_after < rate_before,
        "guard failures should lower hit rate: before={rate_before}, after={rate_after}"
    );
}

#[test]
fn guard_failure_rehashes() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_gf_hash");
    profile.record_access(1);
    let hash_before = profile.content_hash;
    // record_guard_failure doesn't change total_accesses/state so hash stays same
    // (hash depends on offset, kind, scope_id, state, accesses only)
    profile.record_guard_failure();
    // Hash depends on offset, kind, scope_id, state, accesses — not guard_failure_count
    // so it should remain the same.
    assert_eq!(profile.content_hash, hash_before);
}

// =========================================================================
// IcSiteProfile — ColdEntryPruning family
// (tested through decide_bailout where low hit rate triggers PruneColdEntries)
// =========================================================================

#[test]
fn cold_entry_pruning_via_low_hit_rate() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_cold");
    // Create many transitions (shape changes) relative to total accesses
    // to produce a low hit rate.
    for shape_id in 1..=3u64 {
        profile.record_access(shape_id);
    }
    // Now do a few more accesses to get past min_access_count
    for _ in 0..98 {
        profile.record_access(1);
    }
    // 3 transitions out of 101 accesses → hit_rate ≈ 970_000
    // That's above default threshold. We need a config with high threshold.
    let config = IcPolicyConfig {
        min_hit_rate_millionths: 990_000, // 99%
        min_access_count: 10,
        max_guard_failures: 100,
        ..IcPolicyConfig::default()
    };
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(
        decision.verdict,
        BailoutVerdict::PruneColdEntries,
        "low hit rate with few transitions should prune: reason={}",
        decision.reason
    );
}

// =========================================================================
// BailoutVerdict
// =========================================================================

#[test]
fn bailout_verdict_all_exhaustive() {
    assert_eq!(BailoutVerdict::ALL.len(), 6);
}

#[test]
fn bailout_verdict_display() {
    for v in BailoutVerdict::ALL {
        let display = format!("{v}");
        assert!(!display.is_empty());
    }
}

#[test]
fn bailout_verdict_invalidation() {
    assert!(!BailoutVerdict::Continue.causes_invalidation());
    assert!(!BailoutVerdict::Widen.causes_invalidation());
    assert!(!BailoutVerdict::PromoteToMegamorphic.causes_invalidation());
    assert!(!BailoutVerdict::PruneColdEntries.causes_invalidation());
    assert!(BailoutVerdict::Deoptimise.causes_invalidation());
    assert!(BailoutVerdict::Recompile.causes_invalidation());
}

#[test]
fn bailout_verdict_serde_round_trip() {
    for v in BailoutVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: BailoutVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// =========================================================================
// IcPolicyConfig
// =========================================================================

#[test]
fn policy_config_default_matches_constants() {
    let config = IcPolicyConfig::default();
    assert_eq!(config.max_poly_entries, DEFAULT_MAX_POLY_ENTRIES);
    assert_eq!(config.min_hit_rate_millionths, DEFAULT_MIN_WARM_HIT_RATE);
    assert_eq!(config.min_access_count, DEFAULT_MIN_ACCESS_COUNT);
    assert_eq!(config.megamorphic_threshold, DEFAULT_MEGAMORPHIC_THRESHOLD);
    assert_eq!(
        config.cold_prune_threshold_millionths,
        DEFAULT_COLD_PRUNE_THRESHOLD
    );
    assert!(config.megamorphic_sticky);
}

#[test]
fn policy_config_serde_round_trip() {
    let config = IcPolicyConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: IcPolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// =========================================================================
// decide_bailout — BailoutDecisionLogic family
// =========================================================================

#[test]
fn bailout_insufficient_accesses_continues() {
    let profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_cold");
    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(decision.verdict, BailoutVerdict::Continue);
    assert!(decision.reason.contains("insufficient"));
}

#[test]
fn bailout_excessive_guard_failures_deoptimises() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_gf_deopt");
    profile.record_access(1);
    // Fill up enough accesses
    for _ in 0..200 {
        profile.record_access(1);
    }
    // Add guard failures exceeding max
    let config = IcPolicyConfig {
        max_guard_failures: 5,
        ..IcPolicyConfig::default()
    };
    for _ in 0..5 {
        profile.record_guard_failure();
    }
    let epoch = SecurityEpoch::from_raw(2);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(decision.verdict, BailoutVerdict::Deoptimise);
    assert!(decision.reason.contains("guard failures"));
}

#[test]
fn bailout_megamorphic_sticky_continues() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_mega_sticky");
    // Drive to megamorphic
    for shape_id in 1..=(DEFAULT_MAX_POLY_ENTRIES as u64 + 1) {
        profile.record_access(shape_id);
    }
    // Fill enough accesses
    for _ in 0..200 {
        profile.record_access(1);
    }
    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(decision.verdict, BailoutVerdict::Continue);
    assert!(decision.reason.contains("megamorphic"));
}

#[test]
fn bailout_shapes_exceed_megamorphic_threshold_promotes() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_mega_promote");
    // Need megamorphic_sticky = false to not short-circuit
    // Actually, with sticky=true, mega sites continue. So let's set sticky=false.
    let config = IcPolicyConfig {
        megamorphic_sticky: false,
        megamorphic_threshold: 5,
        max_poly_entries: 3,
        min_access_count: 5,
        ..IcPolicyConfig::default()
    };
    // Add shapes beyond mega threshold
    for shape_id in 1..=6u64 {
        profile.record_access(shape_id);
    }
    // Ensure enough accesses
    for _ in 0..10 {
        profile.record_access(1);
    }
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(decision.verdict, BailoutVerdict::PromoteToMegamorphic);
}

#[test]
fn bailout_shapes_exceed_max_poly_promotes() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_poly_promote");
    let config = IcPolicyConfig {
        megamorphic_sticky: false,
        max_poly_entries: 2,
        megamorphic_threshold: 10, // high threshold so poly check hits first
        min_access_count: 5,
        ..IcPolicyConfig::default()
    };
    for shape_id in 1..=3u64 {
        profile.record_access(shape_id);
    }
    for _ in 0..10 {
        profile.record_access(1);
    }
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(decision.verdict, BailoutVerdict::PromoteToMegamorphic);
}

#[test]
fn bailout_transition_count_capped_at_three_from_state_machine() {
    // The IC state machine has 3 state changes max (uninit→mono→poly→mega),
    // so transition_count tops out at 3 via record_access alone.
    // The Recompile path requires transition_count > 3, which can only be
    // achieved via external profile mutation. Here we verify the cap.
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_tc_cap");
    for shape_id in 1..=10u64 {
        profile.record_access(shape_id);
    }
    // uninit→mono(1), mono→poly(2), poly→mega(3), then sticky prevents more
    assert_eq!(profile.transition_count, 3);
}

#[test]
fn bailout_low_hit_rate_few_transitions_prunes() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_prune");
    // 2 shapes → transition_count = 2 (≤3 → PruneColdEntries path)
    profile.record_access(1);
    profile.record_access(2);
    // Now fill to min_access_count with many guard failures to lower hit rate
    for _ in 0..10 {
        profile.record_access(1);
    }
    // total_accesses=12, transition_count=2, guard_failures=0
    // hit_rate = (12 - 2)/12 = 10/12 = 833_333
    let config = IcPolicyConfig {
        min_access_count: 10,
        min_hit_rate_millionths: 900_000, // 90% threshold
        max_poly_entries: 10,
        megamorphic_threshold: 20,
        megamorphic_sticky: false,
        max_guard_failures: 100,
        ..IcPolicyConfig::default()
    };
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(decision.verdict, BailoutVerdict::PruneColdEntries);
}

#[test]
fn bailout_stable_site_continues() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_stable");
    profile.record_access(1);
    for _ in 0..200 {
        profile.record_access(1);
    }
    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    assert_eq!(decision.verdict, BailoutVerdict::Continue);
    assert!(decision.reason.contains("stable"));
}

#[test]
fn bailout_decision_has_correct_fields() {
    let mut profile = IcSiteProfile::new(42, IcSiteKind::CallSite, "fn_fields");
    profile.record_access(1);
    for _ in 0..200 {
        profile.record_access(1);
    }
    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(7);
    let decision = decide_bailout(&profile, &config, epoch);

    assert_eq!(decision.instruction_offset, 42);
    assert_eq!(decision.scope_id, "fn_fields");
    assert_eq!(decision.epoch, epoch);
    assert_eq!(decision.schema_version, PIC_DECISION_SCHEMA_VERSION);
    assert_eq!(decision.site_state, IcSiteState::Monomorphic);
    assert_eq!(decision.observed_shape_count, 1);
    assert!(decision.hit_rate_millionths > 0);
}

#[test]
fn bailout_decision_hash_deterministic() {
    let mut p1 = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_det");
    let mut p2 = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_det");
    for _ in 0..150 {
        p1.record_access(1);
        p2.record_access(1);
    }
    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let d1 = decide_bailout(&p1, &config, epoch);
    let d2 = decide_bailout(&p2, &config, epoch);
    assert_eq!(d1.decision_hash, d2.decision_hash);
    assert_eq!(d1.verdict, d2.verdict);
}

#[test]
fn bailout_decision_different_epoch_different_hash() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_epoch");
    for _ in 0..150 {
        profile.record_access(1);
    }
    let config = IcPolicyConfig::default();
    let d1 = decide_bailout(&profile, &config, SecurityEpoch::from_raw(1));
    let d2 = decide_bailout(&profile, &config, SecurityEpoch::from_raw(2));
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn bailout_decision_serde_round_trip() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_serde");
    for _ in 0..150 {
        profile.record_access(1);
    }
    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let decision = decide_bailout(&profile, &config, epoch);
    let json = serde_json::to_string(&decision).unwrap();
    let back: BailoutDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

// =========================================================================
// IcReplayLog — DeterministicReplay family
// =========================================================================

#[test]
fn replay_log_starts_empty() {
    let log = IcReplayLog::new("scope_a");
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert_eq!(log.megamorphic_transitions(), 0);
    assert_eq!(log.scope_id, "scope_a");
    assert_eq!(log.schema_version, PIC_REPLAY_SCHEMA_VERSION);
}

#[test]
fn replay_log_push_and_len() {
    let mut log = IcReplayLog::new("scope_b");
    log.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());

    log.push(0, IcSiteState::Monomorphic, IcSiteState::Polymorphic, 2, 2);
    assert_eq!(log.len(), 2);
}

#[test]
fn replay_log_sequence_numbers_monotonic() {
    let mut log = IcReplayLog::new("scope_seq");
    for i in 0..5 {
        log.push(
            0,
            IcSiteState::Uninitialised,
            IcSiteState::Monomorphic,
            i + 1,
            i + 1,
        );
    }
    for (i, event) in log.events.iter().enumerate() {
        assert_eq!(event.sequence, i as u64);
    }
}

#[test]
fn replay_log_megamorphic_transitions_count() {
    let mut log = IcReplayLog::new("scope_mega");
    log.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    log.push(0, IcSiteState::Monomorphic, IcSiteState::Polymorphic, 2, 2);
    log.push(0, IcSiteState::Polymorphic, IcSiteState::Megamorphic, 3, 3);
    assert_eq!(log.megamorphic_transitions(), 1);
}

#[test]
fn replay_log_deterministic_hash() {
    let mut log1 = IcReplayLog::new("scope_det");
    let mut log2 = IcReplayLog::new("scope_det");
    log1.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    log2.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    assert_eq!(log1.content_hash, log2.content_hash);
}

#[test]
fn replay_log_different_scope_different_hash() {
    let mut log1 = IcReplayLog::new("scope_x");
    let mut log2 = IcReplayLog::new("scope_y");
    log1.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    log2.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    assert_ne!(log1.content_hash, log2.content_hash);
}

#[test]
fn replay_log_serde_round_trip() {
    let mut log = IcReplayLog::new("scope_serde");
    log.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    log.push(0, IcSiteState::Monomorphic, IcSiteState::Polymorphic, 2, 2);
    let json = serde_json::to_string(&log).unwrap();
    let back: IcReplayLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

// =========================================================================
// IcScopeProfile — ScopeAggregation family
// =========================================================================

#[test]
fn scope_profile_starts_empty() {
    let scope = IcScopeProfile::new("fn_empty");
    assert_eq!(scope.site_count(), 0);
    assert_eq!(scope.monomorphic_count(), 0);
    assert_eq!(scope.megamorphic_count(), 0);
    assert_eq!(scope.total_accesses, 0);
    assert_eq!(scope.total_guard_failures, 0);
    assert_eq!(scope.monomorphic_rate_millionths(), 0);
}

#[test]
fn scope_profile_register_and_access() {
    let mut scope = IcScopeProfile::new("fn_reg");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(4, IcSiteKind::CallSite);
    assert_eq!(scope.site_count(), 2);

    let changed = scope.record_access(0, 42);
    assert!(changed, "first access should transition uninit→mono");
    assert_eq!(scope.total_accesses, 1);
    assert_eq!(scope.monomorphic_count(), 1);
}

#[test]
fn scope_profile_access_to_unregistered_site_noop() {
    let mut scope = IcScopeProfile::new("fn_unreg");
    let changed = scope.record_access(99, 1);
    assert!(!changed);
    assert_eq!(scope.total_accesses, 1); // total still incremented
}

#[test]
fn scope_profile_guard_failure_aggregation() {
    let mut scope = IcScopeProfile::new("fn_gf_agg");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(4, IcSiteKind::PropertyStore);
    scope.record_guard_failure(0);
    scope.record_guard_failure(0);
    scope.record_guard_failure(4);
    assert_eq!(scope.total_guard_failures, 3);
    assert_eq!(scope.sites.get(&0).unwrap().guard_failure_count, 2);
    assert_eq!(scope.sites.get(&4).unwrap().guard_failure_count, 1);
}

#[test]
fn scope_profile_monomorphic_rate() {
    let mut scope = IcScopeProfile::new("fn_mono_rate");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(4, IcSiteKind::PropertyStore);
    // Site 0: monomorphic (1 shape)
    scope.record_access(0, 1);
    // Site 4: polymorphic (2 shapes)
    scope.record_access(4, 1);
    scope.record_access(4, 2);

    assert_eq!(scope.monomorphic_count(), 1);
    let rate = scope.monomorphic_rate_millionths();
    // 1 mono out of 2 sites → 500_000
    assert_eq!(rate, 500_000);
}

#[test]
fn scope_profile_megamorphic_count() {
    let mut scope = IcScopeProfile::new("fn_mega_cnt");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    for shape_id in 1..=(DEFAULT_MAX_POLY_ENTRIES as u64 + 1) {
        scope.record_access(0, shape_id);
    }
    assert_eq!(scope.megamorphic_count(), 1);
}

#[test]
fn scope_profile_replay_log_records_transitions() {
    let mut scope = IcScopeProfile::new("fn_replay");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.record_access(0, 1); // uninit → mono
    scope.record_access(0, 2); // mono → poly
    assert_eq!(scope.replay_log.len(), 2);
    assert_eq!(
        scope.replay_log.events[0].from_state,
        IcSiteState::Uninitialised
    );
    assert_eq!(
        scope.replay_log.events[0].to_state,
        IcSiteState::Monomorphic
    );
    assert_eq!(
        scope.replay_log.events[1].from_state,
        IcSiteState::Monomorphic
    );
    assert_eq!(
        scope.replay_log.events[1].to_state,
        IcSiteState::Polymorphic
    );
}

#[test]
fn scope_profile_evaluate_all_returns_only_warm_sites() {
    let mut scope = IcScopeProfile::new("fn_eval");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(4, IcSiteKind::CallSite);

    // Site 0: warm (>=100 accesses)
    for _ in 0..150 {
        scope.record_access(0, 1);
    }
    // Site 4: cold (1 access)
    scope.record_access(4, 1);

    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let decisions = scope.evaluate_all(&config, epoch);
    assert_eq!(decisions.len(), 1, "only warm site should be evaluated");
    assert_eq!(decisions[0].instruction_offset, 0);
}

#[test]
fn scope_profile_evaluate_all_deterministic() {
    let mut s1 = IcScopeProfile::new("fn_det_eval");
    let mut s2 = IcScopeProfile::new("fn_det_eval");
    for scope in [&mut s1, &mut s2] {
        scope.register_site(0, IcSiteKind::PropertyLoad);
        scope.register_site(4, IcSiteKind::CallSite);
        for _ in 0..200 {
            scope.record_access(0, 1);
            scope.record_access(4, 1);
        }
    }
    let config = IcPolicyConfig::default();
    let epoch = SecurityEpoch::from_raw(1);
    let d1 = s1.evaluate_all(&config, epoch);
    let d2 = s2.evaluate_all(&config, epoch);
    assert_eq!(d1.len(), d2.len());
    for (a, b) in d1.iter().zip(d2.iter()) {
        assert_eq!(a.decision_hash, b.decision_hash);
    }
}

#[test]
fn scope_profile_serde_round_trip() {
    let mut scope = IcScopeProfile::new("fn_serde_scope");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.record_access(0, 1);
    scope.record_access(0, 2);
    let json = serde_json::to_string(&scope).unwrap();
    let back: IcScopeProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(scope, back);
}

// =========================================================================
// End-to-end integration scenarios
// =========================================================================

#[test]
fn end_to_end_mono_to_mega_full_lifecycle() {
    let mut scope = IcScopeProfile::new("fn_lifecycle");
    scope.register_site(0, IcSiteKind::PropertyLoad);

    // Phase 1: Monomorphic warmup
    scope.record_access(0, 1);
    assert_eq!(
        scope.sites.get(&0).unwrap().current_state,
        IcSiteState::Monomorphic
    );

    // Phase 2: Polymorphic expansion
    scope.record_access(0, 2);
    scope.record_access(0, 3);
    assert_eq!(
        scope.sites.get(&0).unwrap().current_state,
        IcSiteState::Polymorphic
    );

    // Phase 3: Megamorphic blowout
    for shape_id in 4..=10u64 {
        scope.record_access(0, shape_id);
    }
    assert_eq!(
        scope.sites.get(&0).unwrap().current_state,
        IcSiteState::Megamorphic
    );

    // Phase 4: Replay log captured all transitions
    assert!(scope.replay_log.len() >= 3); // uninit→mono, mono→poly, poly→mega
    assert_eq!(scope.replay_log.megamorphic_transitions(), 1);

    // Phase 5: Warm up for evaluation
    for _ in 0..200 {
        scope.record_access(0, 1);
    }
    let config = IcPolicyConfig::default();
    let decisions = scope.evaluate_all(&config, SecurityEpoch::from_raw(1));
    assert_eq!(decisions.len(), 1);
    // Megamorphic sticky → Continue
    assert_eq!(decisions[0].verdict, BailoutVerdict::Continue);
}

#[test]
fn end_to_end_multi_site_deopt_cascade() {
    let mut scope = IcScopeProfile::new("fn_cascade");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(8, IcSiteKind::PropertyStore);
    scope.register_site(16, IcSiteKind::CallSite);

    // Warm up all sites
    for _ in 0..200 {
        scope.record_access(0, 1);
        scope.record_access(8, 1);
        scope.record_access(16, 1);
    }

    // Add excessive guard failures to site 16
    let config = IcPolicyConfig {
        max_guard_failures: 3,
        ..IcPolicyConfig::default()
    };
    for _ in 0..3 {
        scope.record_guard_failure(16);
    }

    let decisions = scope.evaluate_all(&config, SecurityEpoch::from_raw(1));
    assert_eq!(decisions.len(), 3);

    // Sites 0 and 8 should continue; site 16 should deoptimise
    let deopt_decisions: Vec<_> = decisions
        .iter()
        .filter(|d| d.verdict == BailoutVerdict::Deoptimise)
        .collect();
    assert_eq!(deopt_decisions.len(), 1);
    assert_eq!(deopt_decisions[0].instruction_offset, 16);
}

#[test]
fn end_to_end_replay_determinism_across_runs() {
    // Run the same access pattern twice; replay logs must match.
    let shapes = [1u64, 2, 3, 1, 2, 4, 5, 1, 2, 3];
    let mut scope1 = IcScopeProfile::new("fn_replay_det");
    let mut scope2 = IcScopeProfile::new("fn_replay_det");
    for scope in [&mut scope1, &mut scope2] {
        scope.register_site(0, IcSiteKind::PropertyLoad);
        for &shape in &shapes {
            scope.record_access(0, shape);
        }
    }
    assert_eq!(scope1.replay_log, scope2.replay_log);
    assert_eq!(
        scope1.replay_log.content_hash,
        scope2.replay_log.content_hash
    );
}

// =========================================================================
// PicSpecimenFamily
// =========================================================================

#[test]
fn pic_specimen_family_all_exhaustive() {
    assert_eq!(PicSpecimenFamily::ALL.len(), 8);
}

#[test]
fn pic_specimen_family_display_matches_as_str() {
    for family in PicSpecimenFamily::ALL {
        assert_eq!(format!("{family}"), family.as_str());
    }
}

#[test]
fn pic_specimen_family_serde_round_trip() {
    for family in PicSpecimenFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let back: PicSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, back);
    }
}

// =========================================================================
// PicExpectedOutcome and PicVerdict
// =========================================================================

#[test]
fn pic_expected_outcome_serde_round_trip() {
    let outcomes = [
        PicExpectedOutcome::MonomorphicHit,
        PicExpectedOutcome::PolymorphicHit,
        PicExpectedOutcome::MegamorphicPromotion,
        PicExpectedOutcome::GuardFailureDetected,
        PicExpectedOutcome::BailoutTriggered,
        PicExpectedOutcome::StableProfile,
        PicExpectedOutcome::ReplayMatch,
        PicExpectedOutcome::ScopeMetricsCorrect,
    ];
    for outcome in &outcomes {
        let json = serde_json::to_string(outcome).unwrap();
        let back: PicExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, back);
    }
}

#[test]
fn pic_verdict_serde_round_trip() {
    for verdict in [PicVerdict::Pass, PicVerdict::Fail] {
        let json = serde_json::to_string(&verdict).unwrap();
        let back: PicVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }
}

// =========================================================================
// PicEvidenceInventory
// =========================================================================

#[test]
fn evidence_inventory_contract_satisfied_with_all_pass() {
    let inventory = PicEvidenceInventory {
        schema_version: PIC_SCHEMA_VERSION.into(),
        component: COMPONENT.into(),
        specimen_count: 3,
        pass_count: 3,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![
            PicSpecimenResult {
                family: PicSpecimenFamily::MonomorphicFastPath,
                name: "test1".into(),
                verdict: PicVerdict::Pass,
                detail: "ok".into(),
            },
            PicSpecimenResult {
                family: PicSpecimenFamily::PolymorphicInBounds,
                name: "test2".into(),
                verdict: PicVerdict::Pass,
                detail: "ok".into(),
            },
            PicSpecimenResult {
                family: PicSpecimenFamily::DeterministicReplay,
                name: "test3".into(),
                verdict: PicVerdict::Pass,
                detail: "ok".into(),
            },
        ],
    };
    assert!(inventory.contract_satisfied());
}

#[test]
fn evidence_inventory_contract_not_satisfied_with_failure() {
    let inventory = PicEvidenceInventory {
        schema_version: PIC_SCHEMA_VERSION.into(),
        component: COMPONENT.into(),
        specimen_count: 2,
        pass_count: 1,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![
            PicSpecimenResult {
                family: PicSpecimenFamily::GuardFailure,
                name: "test1".into(),
                verdict: PicVerdict::Pass,
                detail: "ok".into(),
            },
            PicSpecimenResult {
                family: PicSpecimenFamily::BailoutDecisionLogic,
                name: "test2".into(),
                verdict: PicVerdict::Fail,
                detail: "mismatch".into(),
            },
        ],
    };
    assert!(!inventory.contract_satisfied());
}

#[test]
fn evidence_inventory_contract_not_satisfied_when_empty() {
    let inventory = PicEvidenceInventory {
        schema_version: PIC_SCHEMA_VERSION.into(),
        component: COMPONENT.into(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: Vec::new(),
    };
    assert!(!inventory.contract_satisfied());
}

#[test]
fn evidence_inventory_serde_round_trip() {
    let mut coverage = BTreeMap::new();
    coverage.insert(PicSpecimenFamily::MonomorphicFastPath, 2);
    coverage.insert(PicSpecimenFamily::ScopeAggregation, 1);
    let inventory = PicEvidenceInventory {
        schema_version: PIC_SCHEMA_VERSION.into(),
        component: COMPONENT.into(),
        specimen_count: 3,
        pass_count: 3,
        fail_count: 0,
        family_coverage: coverage,
        evidence: vec![PicSpecimenResult {
            family: PicSpecimenFamily::MonomorphicFastPath,
            name: "test_mono".into(),
            verdict: PicVerdict::Pass,
            detail: "correct".into(),
        }],
    };
    let json = serde_json::to_string(&inventory).unwrap();
    let back: PicEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, back);
}

// =========================================================================
// IcSiteProfile edge cases
// =========================================================================

#[test]
fn profile_zero_accesses_hit_rate_is_zero() {
    let profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_zero");
    assert_eq!(profile.hit_rate_millionths(), 0);
}

#[test]
fn profile_is_warm_boundary() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_warm");
    for _ in 0..(DEFAULT_MIN_ACCESS_COUNT - 1) {
        profile.record_access(1);
    }
    assert!(!profile.is_warm());
    profile.record_access(1);
    assert!(profile.is_warm());
}

#[test]
fn profile_schema_version_set_on_creation() {
    let profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_schema");
    assert_eq!(profile.schema_version, PIC_PROFILE_SCHEMA_VERSION);
}

#[test]
fn profile_serde_round_trip() {
    let mut profile = IcSiteProfile::new(10, IcSiteKind::ComputedStore, "fn_serde_prof");
    profile.record_access(1);
    profile.record_access(2);
    profile.record_guard_failure();
    let json = serde_json::to_string(&profile).unwrap();
    let back: IcSiteProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

// =========================================================================
// Stress: many sites, many shapes
// =========================================================================

#[test]
fn stress_many_sites_in_scope() {
    let mut scope = IcScopeProfile::new("fn_stress");
    for offset in 0..50u32 {
        scope.register_site(offset * 4, IcSiteKind::PropertyLoad);
    }
    assert_eq!(scope.site_count(), 50);

    // Access each site with its offset as shape
    for offset in 0..50u32 {
        scope.record_access(offset * 4, offset as u64);
    }
    assert_eq!(scope.monomorphic_count(), 50);
    assert_eq!(scope.monomorphic_rate_millionths(), 1_000_000);
}

#[test]
fn stress_many_shapes_at_single_site() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_many_shapes");
    for shape_id in 1..=100u64 {
        profile.record_access(shape_id);
    }
    assert_eq!(profile.observed_shapes.len(), 100);
    assert!(profile.is_megamorphic());
}

#[test]
fn stress_high_access_count() {
    let mut profile = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_high_access");
    for _ in 0..10_000u64 {
        profile.record_access(1);
    }
    assert_eq!(profile.total_accesses, 10_000);
    let rate = profile.hit_rate_millionths();
    // 1 transition out of 10_000 → very high hit rate
    assert!(rate > 999_000);
}
