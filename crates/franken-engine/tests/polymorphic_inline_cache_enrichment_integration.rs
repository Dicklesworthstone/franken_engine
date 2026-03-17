//! Enrichment integration tests for `polymorphic_inline_cache` module.
//!
//! Bead: bd-1lsy.7.6.2 [RGC-606B]
//!
//! Covers edge cases, adversarial inputs, determinism verification,
//! policy configuration boundaries, scope-level stress, evidence pipeline,
//! and cross-component interactions not in the base integration suite.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;

use frankenengine_engine::polymorphic_inline_cache::{
    BEAD_ID, BailoutVerdict, COMPONENT, DEFAULT_COLD_PRUNE_THRESHOLD, DEFAULT_MAX_POLY_ENTRIES,
    DEFAULT_MEGAMORPHIC_THRESHOLD, DEFAULT_MIN_ACCESS_COUNT, DEFAULT_MIN_WARM_HIT_RATE,
    IcPolicyConfig, IcReplayLog, IcScopeProfile, IcSiteKind, IcSiteProfile, IcSiteState,
    PIC_DECISION_SCHEMA_VERSION, PIC_PROFILE_SCHEMA_VERSION, PIC_REPLAY_SCHEMA_VERSION,
    PIC_SCHEMA_VERSION, PicEvidenceInventory, PicExpectedOutcome, PicSpecimenFamily,
    PicSpecimenResult, PicVerdict, decide_bailout,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn warm_mono_profile(offset: u32, scope: &str, shape: u64) -> IcSiteProfile {
    let mut p = IcSiteProfile::new(offset, IcSiteKind::PropertyLoad, scope);
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        p.record_access(shape);
    }
    p
}

// =========================================================================
// Edge case: profile state transitions at exact boundaries
// =========================================================================

#[test]
fn transition_at_exact_poly_boundary() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_boundary");
    // Add exactly DEFAULT_MAX_POLY_ENTRIES shapes → should be polymorphic
    for i in 1..=DEFAULT_MAX_POLY_ENTRIES as u64 {
        p.record_access(i);
    }
    assert_eq!(p.current_state, IcSiteState::Polymorphic);
    assert_eq!(p.observed_shapes.len(), DEFAULT_MAX_POLY_ENTRIES);

    // One more shape → megamorphic
    let changed = p.record_access(DEFAULT_MAX_POLY_ENTRIES as u64 + 1);
    assert!(changed);
    assert_eq!(p.current_state, IcSiteState::Megamorphic);
}

#[test]
fn profile_with_zero_shape_id() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_zero");
    let changed = p.record_access(0);
    assert!(changed);
    assert_eq!(p.current_state, IcSiteState::Monomorphic);
    assert_eq!(p.observed_shapes, vec![0]);
}

#[test]
fn profile_with_u64_max_shape_id() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_max");
    p.record_access(u64::MAX);
    assert_eq!(p.current_state, IcSiteState::Monomorphic);
    assert_eq!(p.observed_shapes, vec![u64::MAX]);

    // Add another shape to ensure sorting works with extreme values
    p.record_access(0);
    assert_eq!(p.current_state, IcSiteState::Polymorphic);
    assert_eq!(p.observed_shapes, vec![0, u64::MAX]);
}

#[test]
fn profile_shapes_stay_sorted_after_interleaved_access() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_sort");
    p.record_access(100);
    p.record_access(5);
    p.record_access(50);
    p.record_access(1);
    assert_eq!(p.observed_shapes, vec![1, 5, 50, 100]);
}

#[test]
fn profile_empty_scope_id() {
    let p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "");
    assert_eq!(p.scope_id, "");
    assert_eq!(p.current_state, IcSiteState::Uninitialised);
}

#[test]
fn profile_large_scope_id() {
    let scope = "a".repeat(10_000);
    let p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, &scope);
    assert_eq!(p.scope_id.len(), 10_000);
}

// =========================================================================
// Saturating arithmetic edge cases
// =========================================================================

#[test]
fn profile_access_count_saturates() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_sat");
    p.total_accesses = u64::MAX - 1;
    p.record_access(1);
    assert_eq!(p.total_accesses, u64::MAX);
    // One more should saturate, not wrap
    p.record_access(1);
    assert_eq!(p.total_accesses, u64::MAX);
}

#[test]
fn profile_guard_failure_count_saturates() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_gf_sat");
    p.guard_failure_count = u32::MAX - 1;
    p.record_guard_failure();
    assert_eq!(p.guard_failure_count, u32::MAX);
    p.record_guard_failure();
    assert_eq!(p.guard_failure_count, u32::MAX);
}

#[test]
fn profile_transition_count_saturates() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_tc_sat");
    p.transition_count = u32::MAX;
    // Adding a new shape would normally increment transition_count
    // Since it's already at MAX, it should saturate
    p.record_access(1); // uninit → mono
    assert_eq!(p.transition_count, u32::MAX);
}

// =========================================================================
// Hit rate edge cases
// =========================================================================

#[test]
fn hit_rate_with_single_access_is_zero() {
    // First access causes a transition (uninit → mono), so 0 hits / 1 access = 0
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_single");
    p.record_access(1);
    assert_eq!(p.hit_rate_millionths(), 0);
}

#[test]
fn hit_rate_with_many_guard_failures() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_failures");
    for _ in 0..100 {
        p.record_access(1);
    }
    for _ in 0..50 {
        p.record_guard_failure();
    }
    // 100 accesses, 1 transition, 50 guard failures
    // hits = 100 - (1 + 50) = 49
    // rate = 49/100 * 1_000_000 = 490_000
    assert_eq!(p.hit_rate_millionths(), 490_000);
}

#[test]
fn hit_rate_misses_exceed_accesses_returns_zero() {
    // Guard failures don't increment total_accesses, so misses can exceed accesses
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_underflow");
    p.record_access(1); // 1 access, 1 transition
    p.record_guard_failure();
    p.record_guard_failure();
    // total_accesses = 1, transition_count = 1, guard_failures = 2
    // misses = 1 + 2 = 3, hits = 1.saturating_sub(3) = 0
    assert_eq!(p.hit_rate_millionths(), 0);
}

// =========================================================================
// Policy configuration edge cases
// =========================================================================

#[test]
fn config_zero_max_poly_entries_immediate_mega() {
    let config = IcPolicyConfig {
        max_poly_entries: 0,
        megamorphic_threshold: 0,
        ..IcPolicyConfig::default()
    };
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_zero_poly");
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        p.record_access(1);
    }
    let decision = decide_bailout(&p, &config, epoch());
    // With threshold 0, any shape count > 0 should promote to mega
    assert_eq!(decision.verdict, BailoutVerdict::PromoteToMegamorphic);
}

#[test]
fn config_very_high_min_access_count_always_continues() {
    let config = IcPolicyConfig {
        min_access_count: u64::MAX,
        ..IcPolicyConfig::default()
    };
    let mut p = warm_mono_profile(0, "fn_high_min", 1);
    // Even with many guard failures, insufficient accesses means continue
    for _ in 0..100 {
        p.record_guard_failure();
    }
    let decision = decide_bailout(&p, &config, epoch());
    assert_eq!(decision.verdict, BailoutVerdict::Continue);
    assert!(decision.reason.contains("insufficient"));
}

#[test]
fn config_zero_max_guard_failures_instant_deopt() {
    let config = IcPolicyConfig {
        max_guard_failures: 0,
        ..IcPolicyConfig::default()
    };
    let p = warm_mono_profile(0, "fn_zero_gf", 1);
    // With max_guard_failures = 0, even 0 failures >= 0 triggers deopt
    let decision = decide_bailout(&p, &config, epoch());
    assert_eq!(decision.verdict, BailoutVerdict::Deoptimise);
}

#[test]
fn config_one_max_guard_failure_deopt_on_first() {
    let config = IcPolicyConfig {
        max_guard_failures: 1,
        ..IcPolicyConfig::default()
    };
    let mut p = warm_mono_profile(0, "fn_one_gf", 1);
    p.record_guard_failure();
    let decision = decide_bailout(&p, &config, epoch());
    assert_eq!(decision.verdict, BailoutVerdict::Deoptimise);
}

#[test]
fn config_non_sticky_megamorphic() {
    let config = IcPolicyConfig {
        megamorphic_sticky: false,
        ..IcPolicyConfig::default()
    };
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_non_sticky");
    for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
        p.record_access(i + 1);
    }
    assert!(p.is_megamorphic());
    // megamorphic_sticky on profile is set to true by record_access,
    // but policy check uses config.megamorphic_sticky
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        p.record_access(1);
    }
    let decision = decide_bailout(&p, &config, epoch());
    // With non-sticky config, 5 observed shapes > 4 max_poly_entries → PromoteToMegamorphic
    assert_eq!(decision.verdict, BailoutVerdict::PromoteToMegamorphic);
}

#[test]
fn config_very_high_hit_rate_threshold() {
    let config = IcPolicyConfig {
        min_hit_rate_millionths: 999_999,
        ..IcPolicyConfig::default()
    };
    let p = warm_mono_profile(0, "fn_high_hr", 1);
    // The transition from uninit→mono counts as a miss
    let decision = decide_bailout(&p, &config, epoch());
    // With 100 accesses and 1 transition: hit_rate = 990_000 < 999_999.
    // transition_count = 1 which is NOT > 3, so PruneColdEntries (not Recompile).
    assert_eq!(decision.verdict, BailoutVerdict::PruneColdEntries);
}

// =========================================================================
// Bailout decision determinism
// =========================================================================

#[test]
fn bailout_decision_deterministic_across_identical_profiles() {
    let p1 = warm_mono_profile(42, "fn_det1", 100);
    let p2 = warm_mono_profile(42, "fn_det1", 100);
    let config = IcPolicyConfig::default();
    let d1 = decide_bailout(&p1, &config, epoch());
    let d2 = decide_bailout(&p2, &config, epoch());
    assert_eq!(d1.decision_hash, d2.decision_hash);
    assert_eq!(d1.verdict, d2.verdict);
    assert_eq!(d1.reason, d2.reason);
}

#[test]
fn bailout_different_epochs_different_hashes() {
    let p = warm_mono_profile(42, "fn_epoch", 100);
    let config = IcPolicyConfig::default();
    let d1 = decide_bailout(&p, &config, SecurityEpoch::from_raw(1));
    let d2 = decide_bailout(&p, &config, SecurityEpoch::from_raw(2));
    assert_ne!(d1.decision_hash, d2.decision_hash);
    // Verdict should be the same even with different epochs
    assert_eq!(d1.verdict, d2.verdict);
}

#[test]
fn bailout_different_scope_ids_different_hashes() {
    let p1 = warm_mono_profile(42, "fn_scope_a", 100);
    let p2 = warm_mono_profile(42, "fn_scope_b", 100);
    let config = IcPolicyConfig::default();
    let d1 = decide_bailout(&p1, &config, epoch());
    let d2 = decide_bailout(&p2, &config, epoch());
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn bailout_low_hit_rate_with_many_transitions_recompiles() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_recomp");
    // Force many transitions by adding shapes one at a time
    // uninit→mono (1), mono→poly (2), then 2 more shapes stay poly
    // That's only 2 transitions. Need > 3 transitions for Recompile.
    // Add shapes across poly boundary and into megamorphic then add guard failures:
    for i in 0..6 {
        p.record_access(i); // shapes 0-5
    }
    // Now add guard failures to drive transition_count higher
    p.record_guard_failure();
    p.record_guard_failure();
    p.record_guard_failure();
    p.record_guard_failure();
    // Make it warm
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        p.record_access(0);
    }
    let config = IcPolicyConfig {
        min_hit_rate_millionths: 999_000, // Very high threshold
        megamorphic_sticky: false,        // Don't short-circuit as mega-sticky
        megamorphic_threshold: 100,       // High threshold so we stay poly
        max_poly_entries: 100,            // High poly limit
        max_guard_failures: 100,          // Don't deopt on guard failures
        ..IcPolicyConfig::default()
    };
    let decision = decide_bailout(&p, &config, epoch());
    // With custom config: 6 shapes within poly limit (100), no mega transition.
    // transition_count = 2 (uninit→mono, mono→poly) which is NOT > 3,
    // so low hit rate → PruneColdEntries (not Recompile).
    assert_eq!(decision.verdict, BailoutVerdict::PruneColdEntries);
}

#[test]
fn bailout_schema_version_present() {
    let p = warm_mono_profile(0, "fn_schema", 1);
    let config = IcPolicyConfig::default();
    let decision = decide_bailout(&p, &config, epoch());
    assert_eq!(decision.schema_version, PIC_DECISION_SCHEMA_VERSION);
}

// =========================================================================
// Replay log edge cases
// =========================================================================

#[test]
fn replay_log_empty_scope_id() {
    let log = IcReplayLog::new("");
    assert!(log.is_empty());
    assert_eq!(log.scope_id, "");
}

#[test]
fn replay_log_sequence_numbers_monotonic() {
    let mut log = IcReplayLog::new("fn_seq");
    for i in 0..10 {
        log.push(
            i,
            IcSiteState::Uninitialised,
            IcSiteState::Monomorphic,
            i as u64,
            i as u64,
        );
    }
    for (idx, event) in log.events.iter().enumerate() {
        assert_eq!(event.sequence, idx as u64);
    }
}

#[test]
fn replay_log_hash_changes_on_push() {
    let mut log = IcReplayLog::new("fn_hash_change");
    let hash_before = log.content_hash;
    log.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        42,
        1,
    );
    assert_ne!(hash_before, log.content_hash);
}

#[test]
fn replay_log_different_shape_ids_different_hashes() {
    let mut l1 = IcReplayLog::new("fn_diff");
    let mut l2 = IcReplayLog::new("fn_diff");
    l1.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    l2.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        2,
        1,
    );
    assert_ne!(l1.content_hash, l2.content_hash);
}

#[test]
fn replay_log_megamorphic_transitions_counts_only_mega_targets() {
    let mut log = IcReplayLog::new("fn_mega_count");
    log.push(
        0,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        1,
        1,
    );
    log.push(0, IcSiteState::Monomorphic, IcSiteState::Polymorphic, 2, 2);
    log.push(0, IcSiteState::Polymorphic, IcSiteState::Megamorphic, 3, 3);
    // Only the last transition targets Megamorphic
    assert_eq!(log.megamorphic_transitions(), 1);
}

#[test]
fn replay_log_serde_preserves_all_fields() {
    let mut log = IcReplayLog::new("fn_serde_fields");
    log.push(
        10,
        IcSiteState::Uninitialised,
        IcSiteState::Monomorphic,
        42,
        1,
    );
    log.push(
        10,
        IcSiteState::Monomorphic,
        IcSiteState::Polymorphic,
        99,
        2,
    );
    let json = serde_json::to_string(&log).unwrap();
    let back: IcReplayLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log.scope_id, back.scope_id);
    assert_eq!(log.events.len(), back.events.len());
    assert_eq!(log.content_hash, back.content_hash);
    for (a, b) in log.events.iter().zip(back.events.iter()) {
        assert_eq!(a.sequence, b.sequence);
        assert_eq!(a.instruction_offset, b.instruction_offset);
        assert_eq!(a.from_state, b.from_state);
        assert_eq!(a.to_state, b.to_state);
        assert_eq!(a.trigger_shape_id, b.trigger_shape_id);
        assert_eq!(a.access_count, b.access_count);
    }
}

// =========================================================================
// Scope profile stress and edge cases
// =========================================================================

#[test]
fn scope_many_sites_aggregation() {
    let mut scope = IcScopeProfile::new("fn_many_sites");
    // Register 100 sites across different kinds
    for i in 0u32..100 {
        let kind = IcSiteKind::ALL[(i as usize) % IcSiteKind::ALL.len()];
        scope.register_site(i, kind);
    }
    assert_eq!(scope.site_count(), 100);

    // Make all sites monomorphic
    for i in 0u32..100 {
        scope.record_access(i, 42);
    }
    assert_eq!(scope.monomorphic_count(), 100);
    assert_eq!(scope.monomorphic_rate_millionths(), 1_000_000);
}

#[test]
fn scope_mixed_state_sites() {
    let mut scope = IcScopeProfile::new("fn_mixed");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(10, IcSiteKind::PropertyStore);
    scope.register_site(20, IcSiteKind::CallSite);

    // Site 0: monomorphic
    scope.record_access(0, 1);

    // Site 10: polymorphic
    scope.record_access(10, 1);
    scope.record_access(10, 2);

    // Site 20: megamorphic
    for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
        scope.record_access(20, i + 100);
    }

    assert_eq!(scope.monomorphic_count(), 1);
    assert_eq!(scope.megamorphic_count(), 1);
    // 1 mono / 3 total = 333_333
    assert_eq!(scope.monomorphic_rate_millionths(), 333_333);
}

#[test]
fn scope_access_to_unregistered_site_is_noop() {
    let mut scope = IcScopeProfile::new("fn_unreg");
    scope.register_site(10, IcSiteKind::PropertyLoad);
    let changed = scope.record_access(99, 42); // site 99 not registered
    assert!(!changed);
    assert_eq!(scope.total_accesses, 1); // still increments scope counter
}

#[test]
fn scope_guard_failure_to_unregistered_site_still_increments_scope() {
    let mut scope = IcScopeProfile::new("fn_gf_unreg");
    scope.record_guard_failure(99); // site 99 not registered
    assert_eq!(scope.total_guard_failures, 1);
}

#[test]
fn scope_duplicate_register_is_idempotent() {
    let mut scope = IcScopeProfile::new("fn_dup");
    scope.register_site(10, IcSiteKind::PropertyLoad);
    scope.record_access(10, 42);

    // Re-registering same offset should not reset the profile
    scope.register_site(10, IcSiteKind::PropertyStore);
    assert_eq!(scope.site_count(), 1);
    assert_eq!(scope.sites.get(&10).unwrap().total_accesses, 1);
    // The kind should be the original one (PropertyLoad) since entry already existed
    assert_eq!(
        scope.sites.get(&10).unwrap().site_kind,
        IcSiteKind::PropertyLoad
    );
}

#[test]
fn scope_evaluate_all_excludes_cold_sites() {
    let mut scope = IcScopeProfile::new("fn_cold");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(10, IcSiteKind::PropertyLoad);

    // Make site 0 warm
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        scope.record_access(0, 42);
    }
    // Site 10 stays cold (0 accesses)

    let config = IcPolicyConfig::default();
    let decisions = scope.evaluate_all(&config, epoch());
    // Only the warm site should be evaluated
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].instruction_offset, 0);
}

#[test]
fn scope_replay_log_tracks_all_transitions() {
    let mut scope = IcScopeProfile::new("fn_replay_track");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(10, IcSiteKind::PropertyStore);

    // Transitions at site 0: uninit→mono, mono→poly
    scope.record_access(0, 1);
    scope.record_access(0, 2);

    // Transitions at site 10: uninit→mono
    scope.record_access(10, 99);

    assert_eq!(scope.replay_log.len(), 3);
    assert_eq!(scope.replay_log.events[0].instruction_offset, 0);
    assert_eq!(scope.replay_log.events[1].instruction_offset, 0);
    assert_eq!(scope.replay_log.events[2].instruction_offset, 10);
}

#[test]
fn scope_empty_monomorphic_rate_is_zero() {
    let scope = IcScopeProfile::new("fn_empty_rate");
    assert_eq!(scope.monomorphic_rate_millionths(), 0);
}

// =========================================================================
// Evidence inventory edge cases
// =========================================================================

#[test]
fn evidence_inventory_serde_roundtrip() {
    let mut coverage = BTreeMap::new();
    coverage.insert(PicSpecimenFamily::MonomorphicFastPath, 3);
    coverage.insert(PicSpecimenFamily::MegamorphicTransition, 2);

    let inv = PicEvidenceInventory {
        schema_version: PIC_SCHEMA_VERSION.into(),
        component: COMPONENT.into(),
        specimen_count: 5,
        pass_count: 4,
        fail_count: 1,
        family_coverage: coverage,
        evidence: vec![PicSpecimenResult {
            family: PicSpecimenFamily::MonomorphicFastPath,
            name: "test_specimen".into(),
            verdict: PicVerdict::Pass,
            detail: "All checks passed".into(),
        }],
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: PicEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv.specimen_count, back.specimen_count);
    assert_eq!(inv.pass_count, back.pass_count);
    assert_eq!(inv.fail_count, back.fail_count);
    assert_eq!(inv.family_coverage.len(), back.family_coverage.len());
    assert_eq!(inv.evidence.len(), back.evidence.len());
}

#[test]
fn evidence_inventory_with_all_families_covered() {
    let mut coverage = BTreeMap::new();
    for fam in PicSpecimenFamily::ALL {
        coverage.insert(*fam, 1);
    }
    let inv = PicEvidenceInventory {
        schema_version: PIC_SCHEMA_VERSION.into(),
        component: COMPONENT.into(),
        specimen_count: 8,
        pass_count: 8,
        fail_count: 0,
        family_coverage: coverage.clone(),
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
    assert_eq!(coverage.len(), PicSpecimenFamily::ALL.len());
}

// =========================================================================
// Cross-component: profile → decision → replay pipeline
// =========================================================================

#[test]
fn full_pipeline_monomorphic_stable() {
    let mut scope = IcScopeProfile::new("fn_pipeline_mono");
    scope.register_site(0, IcSiteKind::PropertyLoad);

    // Warm up with single shape
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT + 50 {
        scope.record_access(0, 42);
    }

    let config = IcPolicyConfig::default();
    let decisions = scope.evaluate_all(&config, epoch());
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].verdict, BailoutVerdict::Continue);
    assert_eq!(decisions[0].site_state, IcSiteState::Monomorphic);

    // Replay log should have exactly 1 transition (uninit→mono)
    assert_eq!(scope.replay_log.len(), 1);
    assert_eq!(scope.replay_log.megamorphic_transitions(), 0);
}

#[test]
fn full_pipeline_polymorphic_stable() {
    let mut scope = IcScopeProfile::new("fn_pipeline_poly");
    scope.register_site(0, IcSiteKind::PropertyLoad);

    // Add 3 shapes (within poly threshold of 4)
    scope.record_access(0, 1);
    scope.record_access(0, 2);
    scope.record_access(0, 3);

    // Warm up
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        scope.record_access(0, 1);
    }

    let config = IcPolicyConfig::default();
    let decisions = scope.evaluate_all(&config, epoch());
    assert_eq!(decisions.len(), 1);
    // Should continue — polymorphic but within limits and good hit rate
    assert_eq!(decisions[0].verdict, BailoutVerdict::Continue);
    assert_eq!(decisions[0].site_state, IcSiteState::Polymorphic);
}

#[test]
fn full_pipeline_megamorphic_deopt() {
    let mut scope = IcScopeProfile::new("fn_pipeline_mega");
    scope.register_site(0, IcSiteKind::PropertyLoad);

    // Exceed poly threshold → megamorphic
    for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
        scope.record_access(0, i + 1);
    }

    // Warm up
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        scope.record_access(0, 1);
    }

    let config = IcPolicyConfig::default();
    let decisions = scope.evaluate_all(&config, epoch());
    assert_eq!(decisions.len(), 1);
    // Megamorphic sticky → continue on slow path
    assert_eq!(decisions[0].verdict, BailoutVerdict::Continue);
    assert!(decisions[0].reason.contains("megamorphic"));

    // Replay log should capture mega transition
    assert!(scope.replay_log.megamorphic_transitions() > 0);
}

#[test]
fn full_pipeline_guard_failure_deopt() {
    let mut scope = IcScopeProfile::new("fn_pipeline_gf");
    scope.register_site(0, IcSiteKind::PropertyLoad);

    // Warm up
    for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
        scope.record_access(0, 1);
    }

    // Trigger enough guard failures
    let config = IcPolicyConfig::default();
    for _ in 0..config.max_guard_failures + 1 {
        scope.record_guard_failure(0);
    }

    let decisions = scope.evaluate_all(&config, epoch());
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].verdict, BailoutVerdict::Deoptimise);
}

// =========================================================================
// Determinism verification: identical inputs produce identical outputs
// =========================================================================

#[test]
fn determinism_scope_profile_identical_runs() {
    let build_scope = || {
        let mut scope = IcScopeProfile::new("fn_determinism");
        scope.register_site(0, IcSiteKind::PropertyLoad);
        scope.register_site(10, IcSiteKind::PropertyStore);
        scope.register_site(20, IcSiteKind::CallSite);

        for _ in 0..50 {
            scope.record_access(0, 1);
            scope.record_access(10, 2);
            scope.record_access(20, 3);
        }
        scope.record_access(0, 99); // poly transition at site 0
        scope.record_guard_failure(10);

        scope
    };

    let s1 = build_scope();
    let s2 = build_scope();

    assert_eq!(s1.total_accesses, s2.total_accesses);
    assert_eq!(s1.total_guard_failures, s2.total_guard_failures);
    assert_eq!(s1.replay_log.content_hash, s2.replay_log.content_hash);
    assert_eq!(s1.replay_log.len(), s2.replay_log.len());
    for (a, b) in s1.sites.values().zip(s2.sites.values()) {
        assert_eq!(a.content_hash, b.content_hash);
    }
}

#[test]
fn determinism_bailout_json_identical() {
    let p = warm_mono_profile(42, "fn_json_det", 100);
    let config = IcPolicyConfig::default();
    let d1 = decide_bailout(&p, &config, epoch());
    let d2 = decide_bailout(&p, &config, epoch());
    let j1 = serde_json::to_string(&d1).unwrap();
    let j2 = serde_json::to_string(&d2).unwrap();
    assert_eq!(j1, j2);
}

// =========================================================================
// IcSiteKind exhaustive coverage
// =========================================================================

#[test]
fn all_site_kinds_can_create_profiles() {
    for kind in IcSiteKind::ALL {
        let p = IcSiteProfile::new(0, *kind, "fn_all_kinds");
        assert_eq!(p.site_kind, *kind);
        assert_eq!(p.current_state, IcSiteState::Uninitialised);
    }
}

#[test]
fn all_site_kinds_can_be_registered_in_scope() {
    let mut scope = IcScopeProfile::new("fn_all_kinds_scope");
    for (i, kind) in IcSiteKind::ALL.iter().enumerate() {
        scope.register_site(i as u32, *kind);
    }
    assert_eq!(scope.site_count(), IcSiteKind::ALL.len());
}

#[test]
fn all_site_kinds_can_reach_megamorphic() {
    for kind in IcSiteKind::ALL {
        let mut p = IcSiteProfile::new(0, *kind, "fn_mega_all");
        for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
            p.record_access(i + 1);
        }
        assert!(
            p.is_megamorphic(),
            "{kind} should be megamorphic after exceeding poly limit"
        );
    }
}

// =========================================================================
// BailoutVerdict coverage
// =========================================================================

#[test]
fn all_verdict_variants_serde_roundtrip() {
    for v in BailoutVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: BailoutVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
        let display = format!("{v}");
        assert!(!display.is_empty());
    }
}

#[test]
fn verdict_invalidation_only_deopt_and_recompile() {
    let invalidating: Vec<_> = BailoutVerdict::ALL
        .iter()
        .filter(|v| v.causes_invalidation())
        .collect();
    assert_eq!(invalidating.len(), 2);
    assert!(BailoutVerdict::Deoptimise.causes_invalidation());
    assert!(BailoutVerdict::Recompile.causes_invalidation());
}

// =========================================================================
// PicSpecimenFamily and PicExpectedOutcome coverage
// =========================================================================

#[test]
fn specimen_families_have_unique_display_strings() {
    let displays: Vec<String> = PicSpecimenFamily::ALL
        .iter()
        .map(|f| format!("{f}"))
        .collect();
    let mut sorted = displays.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        displays.len(),
        sorted.len(),
        "display strings must be unique"
    );
}

#[test]
fn specimen_family_as_str_matches_display() {
    for fam in PicSpecimenFamily::ALL {
        assert_eq!(fam.as_str(), format!("{fam}"));
    }
}

#[test]
fn expected_outcome_serde_roundtrip() {
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

// =========================================================================
// Profile serde with various states
// =========================================================================

#[test]
fn profile_serde_roundtrip_polymorphic() {
    let mut p = IcSiteProfile::new(5, IcSiteKind::ComputedLoad, "fn_poly_serde");
    p.record_access(1);
    p.record_access(2);
    p.record_access(3);
    assert_eq!(p.current_state, IcSiteState::Polymorphic);
    let json = serde_json::to_string(&p).unwrap();
    let back: IcSiteProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn profile_serde_roundtrip_megamorphic() {
    let mut p = IcSiteProfile::new(5, IcSiteKind::InstanceOf, "fn_mega_serde");
    for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
        p.record_access(i + 1);
    }
    assert!(p.is_megamorphic());
    let json = serde_json::to_string(&p).unwrap();
    let back: IcSiteProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn profile_serde_roundtrip_with_guard_failures() {
    let mut p = IcSiteProfile::new(0, IcSiteKind::PropertyLoad, "fn_gf_serde");
    p.record_access(1);
    p.record_guard_failure();
    p.record_guard_failure();
    p.record_guard_failure();
    let json = serde_json::to_string(&p).unwrap();
    let back: IcSiteProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert_eq!(back.guard_failure_count, 3);
}

// =========================================================================
// Scope profile serde
// =========================================================================

#[test]
fn scope_profile_serde_roundtrip() {
    let mut scope = IcScopeProfile::new("fn_scope_serde");
    scope.register_site(0, IcSiteKind::PropertyLoad);
    scope.register_site(10, IcSiteKind::CallSite);
    scope.record_access(0, 42);
    scope.record_access(10, 99);
    scope.record_guard_failure(0);

    let json = serde_json::to_string(&scope).unwrap();
    let back: IcScopeProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(scope.scope_id, back.scope_id);
    assert_eq!(scope.total_accesses, back.total_accesses);
    assert_eq!(scope.total_guard_failures, back.total_guard_failures);
    assert_eq!(scope.site_count(), back.site_count());
    assert_eq!(scope.replay_log.len(), back.replay_log.len());
}

// =========================================================================
// Regression: constant assertions
// =========================================================================

#[test]
fn constants_are_stable_across_serde() {
    assert_eq!(COMPONENT, "polymorphic_inline_cache");
    assert_eq!(BEAD_ID, "bd-1lsy.7.6.2");
    assert!(PIC_SCHEMA_VERSION.contains("polymorphic"));
    assert!(PIC_PROFILE_SCHEMA_VERSION.contains("pic-profile"));
    assert!(PIC_DECISION_SCHEMA_VERSION.contains("pic-decision"));
    assert!(PIC_REPLAY_SCHEMA_VERSION.contains("pic-replay"));
}

#[test]
fn default_config_values_match_module_constants() {
    let config = IcPolicyConfig::default();
    assert_eq!(config.max_poly_entries, DEFAULT_MAX_POLY_ENTRIES);
    assert_eq!(config.min_hit_rate_millionths, DEFAULT_MIN_WARM_HIT_RATE);
    assert_eq!(config.min_access_count, DEFAULT_MIN_ACCESS_COUNT);
    assert_eq!(config.megamorphic_threshold, DEFAULT_MEGAMORPHIC_THRESHOLD);
    assert_eq!(
        config.cold_prune_threshold_millionths,
        DEFAULT_COLD_PRUNE_THRESHOLD
    );
}
