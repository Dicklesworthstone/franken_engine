//! Integration tests for `dark_matter_saturation_gate` module.
//!
//! Validates public API, serde contracts, determinism, gate evaluation logic,
//! freshness gating, ratchet widening, evidence emission, and edge cases.

use std::collections::BTreeMap;

use frankenengine_engine::dark_matter_saturation_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: u64 = 1_000_000;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(500)
}

fn make_region(
    id: &str,
    kind: DarkMatterRegionKind,
    mass: u64,
    retired: bool,
) -> DarkMatterRegion {
    DarkMatterRegion {
        region_id: id.to_string(),
        kind,
        mass_millionths: mass,
        retired,
        discovered_at_epoch_secs: 1000,
        retired_at_epoch_secs: if retired { Some(2000) } else { None },
        priority_weight_millionths: MILLION,
    }
}

fn make_observation(ts: u64, active: u64, disc: u64, ret: u64) -> BurndownObservation {
    BurndownObservation {
        timestamp_epoch_secs: ts,
        active_mass_millionths: active,
        cumulative_discovered_millionths: disc,
        cumulative_retired_millionths: ret,
    }
}

/// Build a sequence of burndown observations.
fn build_observations(
    count: usize,
    start_time: u64,
    interval: u64,
    initial_active: u64,
    disc_per_step: u64,
    ret_per_step: u64,
) -> Vec<BurndownObservation> {
    let mut obs = Vec::with_capacity(count);
    let mut cum_disc = 0u64;
    let mut cum_ret = 0u64;
    let mut active = initial_active;
    for i in 0..count {
        obs.push(make_observation(
            start_time + (i as u64) * interval,
            active,
            cum_disc,
            cum_ret,
        ));
        cum_disc = cum_disc.saturating_add(disc_per_step);
        cum_ret = cum_ret.saturating_add(ret_per_step);
        active = active
            .saturating_add(disc_per_step)
            .saturating_sub(ret_per_step);
    }
    obs
}

/// Build a fully wired evaluator.
fn build_evaluator(
    active_mass: u64,
    total_surface: u64,
    observations: Vec<BurndownObservation>,
    config: SaturationConfig,
) -> SaturationGateEvaluator {
    let ep = epoch();
    let mut estimate = DarkMatterEstimate::new(total_surface, ep, 1000);
    if active_mass > 0 {
        estimate.add_region(DarkMatterRegion {
            region_id: "test_region".to_string(),
            kind: DarkMatterRegionKind::UntestedCodePath,
            mass_millionths: active_mass,
            retired: false,
            discovered_at_epoch_secs: 1000,
            retired_at_epoch_secs: None,
            priority_weight_millionths: MILLION,
        });
    }
    let mut tracker = BurndownTracker::new(total_surface, ep);
    for obs in observations {
        tracker.record(obs);
    }
    SaturationGateEvaluator::new(config, estimate, tracker)
}

fn low_dm_config() -> SaturationConfig {
    let mut c = SaturationConfig::default();
    c.min_observations = 3;
    c.min_burndown_velocity_millionths = 10_000;
    c
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(DARK_MATTER_GATE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(DARK_MATTER_GATE_SCHEMA_VERSION.contains("dark-matter"));
}

#[test]
fn bead_id_format() {
    assert!(DARK_MATTER_GATE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "dark_matter_saturation_gate");
}

#[test]
fn default_thresholds_are_sane() {
    assert!(DEFAULT_SATURATION_THRESHOLD > 0);
    assert!(DEFAULT_SATURATION_THRESHOLD <= MILLION);
    assert!(DEFAULT_MAX_STALENESS_HOURS > 0);
    assert!(DEFAULT_MIN_BURNDOWN_VELOCITY > 0);
    assert!(DEFAULT_RATCHET_WIDENING_CEILING > 0);
    assert!(DEFAULT_RATCHET_WIDENING_CEILING <= MILLION);
    assert!(DEFAULT_MIN_OBSERVATIONS > 0);
}

#[test]
fn ratchet_ceiling_below_saturation_threshold() {
    // Ratchet widening should be stricter than saturation
    assert!(DEFAULT_RATCHET_WIDENING_CEILING <= DEFAULT_SATURATION_THRESHOLD);
}

// ---------------------------------------------------------------------------
// DarkMatterRegionKind
// ---------------------------------------------------------------------------

#[test]
fn region_kind_all_count() {
    assert_eq!(DarkMatterRegionKind::ALL.len(), 10);
}

#[test]
fn region_kind_all_unique_names() {
    let mut seen = std::collections::BTreeSet::new();
    for kind in DarkMatterRegionKind::ALL {
        assert!(seen.insert(kind.as_str()), "duplicate: {}", kind.as_str());
    }
}

#[test]
fn region_kind_display_matches_as_str() {
    for kind in DarkMatterRegionKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn region_kind_serde_all_variants() {
    for &kind in DarkMatterRegionKind::ALL {
        let json = serde_json::to_string(&kind).unwrap();
        let back: DarkMatterRegionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

#[test]
fn region_kind_ordering_canonical() {
    // Verify ALL is sorted by Ord
    for w in DarkMatterRegionKind::ALL.windows(2) {
        assert!(w[0] <= w[1]);
    }
}

// ---------------------------------------------------------------------------
// DarkMatterRegion
// ---------------------------------------------------------------------------

#[test]
fn region_effective_mass_active_unit_weight() {
    let r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    assert_eq!(r.effective_mass(), 100_000);
}

#[test]
fn region_effective_mass_retired_is_zero() {
    let r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, true);
    assert_eq!(r.effective_mass(), 0);
}

#[test]
fn region_effective_mass_half_weight() {
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    r.priority_weight_millionths = 500_000; // 0.5x
    assert_eq!(r.effective_mass(), 100_000);
}

#[test]
fn region_effective_mass_zero_weight() {
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    r.priority_weight_millionths = 0;
    assert_eq!(r.effective_mass(), 0);
}

#[test]
fn region_effective_mass_double_weight() {
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    r.priority_weight_millionths = 2_000_000; // 2.0x
    assert_eq!(r.effective_mass(), 200_000);
}

#[test]
fn region_effective_mass_saturating_overflow() {
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, u64::MAX, false);
    r.priority_weight_millionths = u64::MAX;
    // must not panic; result clamped via saturating ops
    let _ = r.effective_mass();
}

#[test]
fn region_content_hash_deterministic() {
    let r1 = make_region("gc_reentry", DarkMatterRegionKind::UnobservedInteraction, 50_000, false);
    let r2 = make_region("gc_reentry", DarkMatterRegionKind::UnobservedInteraction, 50_000, false);
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn region_content_hash_differs_on_id() {
    let r1 = make_region("a", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("b", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn region_content_hash_differs_on_kind() {
    let r1 = make_region("r", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r", DarkMatterRegionKind::UnverifiedInterleaving, 100_000, false);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn region_content_hash_differs_on_mass() {
    let r1 = make_region("r", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn region_content_hash_differs_on_retired() {
    let r1 = make_region("r", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r", DarkMatterRegionKind::UntestedCodePath, 100_000, true);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn region_display_contains_fields() {
    let r = make_region("gc_reentry", DarkMatterRegionKind::UnobservedInteraction, 50_000, false);
    let s = r.to_string();
    assert!(s.contains("gc_reentry"));
    assert!(s.contains("active"));
    assert!(s.contains("50000"));
}

#[test]
fn region_display_retired() {
    let r = make_region("gc_reentry", DarkMatterRegionKind::UnobservedInteraction, 50_000, true);
    let s = r.to_string();
    assert!(s.contains("retired"));
}

#[test]
fn region_serde_roundtrip() {
    let r = make_region("gc_reentry", DarkMatterRegionKind::UnobservedInteraction, 50_000, false);
    let json = serde_json::to_string(&r).unwrap();
    let back: DarkMatterRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn region_serde_retired_roundtrip() {
    let r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, true);
    let json = serde_json::to_string(&r).unwrap();
    let back: DarkMatterRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ---------------------------------------------------------------------------
// DarkMatterEstimate
// ---------------------------------------------------------------------------

#[test]
fn estimate_empty_has_zero_mass() {
    let e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    assert_eq!(e.active_mass(), 0);
    assert_eq!(e.retired_mass(), 0);
    assert_eq!(e.effective_mass(), 0);
    assert_eq!(e.dark_matter_fraction(), 0);
    assert_eq!(e.active_region_count(), 0);
    assert_eq!(e.retired_region_count(), 0);
    assert_eq!(e.total_region_count(), 0);
}

#[test]
fn estimate_active_mass_sum() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 80_000, false));
    e.add_region(make_region("r2", DarkMatterRegionKind::UnverifiedInterleaving, 20_000, false));
    assert_eq!(e.active_mass(), 100_000);
}

#[test]
fn estimate_retired_mass_excluded_from_active() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 80_000, false));
    e.add_region(make_region("r2", DarkMatterRegionKind::UntestedCodePath, 40_000, true));
    assert_eq!(e.active_mass(), 80_000);
    assert_eq!(e.retired_mass(), 40_000);
}

#[test]
fn estimate_dark_matter_fraction_simple() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false));
    // 200_000 / 1_000_000 = 200_000 millionths (20%)
    assert_eq!(e.dark_matter_fraction(), 200_000);
}

#[test]
fn estimate_dark_matter_fraction_zero_surface_is_million() {
    let e = DarkMatterEstimate::new(0, epoch(), 1000);
    assert_eq!(e.dark_matter_fraction(), MILLION);
}

#[test]
fn estimate_region_counts() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 80_000, false));
    e.add_region(make_region("r2", DarkMatterRegionKind::UntestedCodePath, 40_000, true));
    e.add_region(make_region("r3", DarkMatterRegionKind::UnverifiedInterleaving, 20_000, false));
    assert_eq!(e.active_region_count(), 2);
    assert_eq!(e.retired_region_count(), 1);
    assert_eq!(e.total_region_count(), 3);
}

#[test]
fn estimate_mass_by_kind() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 80_000, false));
    e.add_region(make_region("r2", DarkMatterRegionKind::UntestedCodePath, 40_000, true));
    e.add_region(make_region("r3", DarkMatterRegionKind::UnverifiedInterleaving, 20_000, false));
    let by_kind = e.mass_by_kind();
    assert_eq!(by_kind[&DarkMatterRegionKind::UntestedCodePath], (80_000, 40_000));
    assert_eq!(by_kind[&DarkMatterRegionKind::UnverifiedInterleaving], (20_000, 0));
}

#[test]
fn estimate_add_region_overwrites_same_id() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false));
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false));
    assert_eq!(e.total_region_count(), 1);
    assert_eq!(e.active_mass(), 200_000);
}

#[test]
fn estimate_content_hash_deterministic() {
    let mut e1 = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e1.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false));
    let mut e2 = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e2.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false));
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn estimate_content_hash_differs_on_regions() {
    let mut e1 = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e1.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false));
    let mut e2 = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e2.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false));
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn estimate_display_contains_key_fields() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false));
    let s = e.to_string();
    assert!(s.contains("dark_matter_estimate"));
    assert!(s.contains("200000"));
}

#[test]
fn estimate_serde_roundtrip() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false));
    let json = serde_json::to_string(&e).unwrap();
    let back: DarkMatterEstimate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn estimate_effective_mass_with_weight() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    r.priority_weight_millionths = 500_000; // 0.5x
    e.add_region(r);
    assert_eq!(e.effective_mass(), 100_000);
}

// ---------------------------------------------------------------------------
// BurndownObservation
// ---------------------------------------------------------------------------

#[test]
fn observation_content_hash_deterministic() {
    let o1 = make_observation(1000, 200_000, 100_000, 50_000);
    let o2 = make_observation(1000, 200_000, 100_000, 50_000);
    assert_eq!(o1.content_hash(), o2.content_hash());
}

#[test]
fn observation_content_hash_differs_on_timestamp() {
    let o1 = make_observation(1000, 200_000, 100_000, 50_000);
    let o2 = make_observation(1001, 200_000, 100_000, 50_000);
    assert_ne!(o1.content_hash(), o2.content_hash());
}

#[test]
fn observation_serde_roundtrip() {
    let o = make_observation(5000, 300_000, 150_000, 80_000);
    let json = serde_json::to_string(&o).unwrap();
    let back: BurndownObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, o);
}

// ---------------------------------------------------------------------------
// BurndownTracker
// ---------------------------------------------------------------------------

#[test]
fn tracker_empty_defaults() {
    let t = BurndownTracker::new(MILLION, epoch());
    assert_eq!(t.observation_count(), 0);
    assert_eq!(t.latest_active_mass(), 0);
    assert_eq!(t.time_span_secs(), 0);
    assert!(!t.has_enough_observations(1));
    assert_eq!(t.discovery_velocity(10), 0);
    assert_eq!(t.retirement_velocity(10), 0);
}

#[test]
fn tracker_record_in_order() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(100, 500_000, 0, 0));
    t.record(make_observation(200, 400_000, 0, 100_000));
    assert_eq!(t.observation_count(), 2);
    assert_eq!(t.latest_active_mass(), 400_000);
}

#[test]
fn tracker_drops_out_of_order() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(200, 500_000, 0, 0));
    t.record(make_observation(100, 400_000, 0, 0)); // out of order
    assert_eq!(t.observation_count(), 1);
}

#[test]
fn tracker_drops_duplicate_timestamp() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(100, 500_000, 0, 0));
    t.record(make_observation(100, 400_000, 0, 0)); // same timestamp
    assert_eq!(t.observation_count(), 1);
}

#[test]
fn tracker_discovery_velocity_nonzero() {
    let obs = build_observations(10, 1000, 100, 500_000, 10_000, 0);
    let mut t = BurndownTracker::new(MILLION, epoch());
    for o in obs {
        t.record(o);
    }
    let vel = t.discovery_velocity(10);
    assert!(vel > 0);
}

#[test]
fn tracker_retirement_velocity_nonzero() {
    let obs = build_observations(10, 1000, 100, 500_000, 0, 10_000);
    let mut t = BurndownTracker::new(MILLION, epoch());
    for o in obs {
        t.record(o);
    }
    let vel = t.retirement_velocity(10);
    assert!(vel > 0);
}

#[test]
fn tracker_net_burndown_positive_when_ret_exceeds_disc() {
    let obs = build_observations(10, 1000, 100, 500_000, 5_000, 15_000);
    let mut t = BurndownTracker::new(MILLION, epoch());
    for o in obs {
        t.record(o);
    }
    let (vel, positive) = t.net_burndown_velocity(10);
    assert!(positive);
    assert!(vel > 0);
}

#[test]
fn tracker_net_burndown_negative_when_disc_exceeds_ret() {
    let obs = build_observations(10, 1000, 100, 500_000, 15_000, 5_000);
    let mut t = BurndownTracker::new(MILLION, epoch());
    for o in obs {
        t.record(o);
    }
    let (_vel, positive) = t.net_burndown_velocity(10);
    assert!(!positive);
}

#[test]
fn tracker_latest_dark_matter_fraction() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(100, 300_000, 0, 0));
    assert_eq!(t.latest_dark_matter_fraction(), 300_000);
}

#[test]
fn tracker_latest_dark_matter_fraction_zero_surface() {
    let t = BurndownTracker::new(0, epoch());
    assert_eq!(t.latest_dark_matter_fraction(), MILLION);
}

#[test]
fn tracker_time_span_secs() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(100, 0, 0, 0));
    t.record(make_observation(500, 0, 0, 0));
    assert_eq!(t.time_span_secs(), 400);
}

#[test]
fn tracker_time_span_single_obs_is_zero() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(100, 0, 0, 0));
    assert_eq!(t.time_span_secs(), 0);
}

#[test]
fn tracker_content_hash_deterministic() {
    let obs = build_observations(5, 1000, 100, 500_000, 10_000, 5_000);
    let mut t1 = BurndownTracker::new(MILLION, epoch());
    let mut t2 = BurndownTracker::new(MILLION, epoch());
    for o in &obs {
        t1.record(o.clone());
        t2.record(o.clone());
    }
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn tracker_content_hash_differs_on_epoch() {
    let obs = build_observations(3, 1000, 100, 500_000, 10_000, 5_000);
    let mut t1 = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    let mut t2 = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(2));
    for o in &obs {
        t1.record(o.clone());
        t2.record(o.clone());
    }
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn tracker_display_contains_burndown() {
    let t = BurndownTracker::new(MILLION, epoch());
    assert!(t.to_string().contains("burndown"));
}

#[test]
fn tracker_serde_roundtrip() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(100, 300_000, 0, 0));
    t.record(make_observation(200, 250_000, 10_000, 60_000));
    let json = serde_json::to_string(&t).unwrap();
    let back: BurndownTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn tracker_has_enough_observations_boundary() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    assert!(!t.has_enough_observations(1));
    t.record(make_observation(100, 0, 0, 0));
    assert!(t.has_enough_observations(1));
    assert!(!t.has_enough_observations(2));
}

#[test]
fn tracker_velocity_single_observation_is_zero() {
    let mut t = BurndownTracker::new(MILLION, epoch());
    t.record(make_observation(100, 300_000, 0, 0));
    assert_eq!(t.discovery_velocity(10), 0);
    assert_eq!(t.retirement_velocity(10), 0);
}

// ---------------------------------------------------------------------------
// BoardState
// ---------------------------------------------------------------------------

#[test]
fn board_state_all_count() {
    assert_eq!(BoardState::ALL.len(), 3);
}

#[test]
fn board_state_permits_frontier_claim() {
    assert!(BoardState::Saturated.permits_frontier_claim());
    assert!(!BoardState::ScopeLimited.permits_frontier_claim());
    assert!(!BoardState::Stale.permits_frontier_claim());
}

#[test]
fn board_state_display_matches_as_str() {
    for state in BoardState::ALL {
        assert_eq!(state.to_string(), state.as_str());
    }
}

#[test]
fn board_state_serde_all_variants() {
    for &state in BoardState::ALL {
        let json = serde_json::to_string(&state).unwrap();
        let back: BoardState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}

#[test]
fn board_state_specific_labels() {
    assert_eq!(BoardState::Saturated.as_str(), "saturated");
    assert_eq!(BoardState::ScopeLimited.as_str(), "scope_limited");
    assert_eq!(BoardState::Stale.as_str(), "stale");
}

// ---------------------------------------------------------------------------
// SaturationConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_is_valid() {
    let c = SaturationConfig::default();
    assert!(c.validate().is_empty());
}

#[test]
fn config_default_uses_constants() {
    let c = SaturationConfig::default();
    assert_eq!(c.saturation_threshold_millionths, DEFAULT_SATURATION_THRESHOLD);
    assert_eq!(c.max_staleness_hours, DEFAULT_MAX_STALENESS_HOURS);
    assert_eq!(c.min_burndown_velocity_millionths, DEFAULT_MIN_BURNDOWN_VELOCITY);
    assert_eq!(c.ratchet_widening_ceiling_millionths, DEFAULT_RATCHET_WIDENING_CEILING);
    assert_eq!(c.min_observations, DEFAULT_MIN_OBSERVATIONS);
}

#[test]
fn config_validates_saturation_threshold_over_million() {
    let mut c = SaturationConfig::default();
    c.saturation_threshold_millionths = MILLION + 1;
    let v = c.validate();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].field, "saturation_threshold_millionths");
}

#[test]
fn config_validates_ratchet_ceiling_over_million() {
    let mut c = SaturationConfig::default();
    c.ratchet_widening_ceiling_millionths = MILLION + 1;
    let v = c.validate();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].field, "ratchet_widening_ceiling_millionths");
}

#[test]
fn config_validates_zero_min_observations() {
    let mut c = SaturationConfig::default();
    c.min_observations = 0;
    let v = c.validate();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].field, "min_observations");
}

#[test]
fn config_validates_zero_velocity_window() {
    let mut c = SaturationConfig::default();
    c.velocity_window = 0;
    let v = c.validate();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].field, "velocity_window");
}

#[test]
fn config_validates_zero_max_staleness() {
    let mut c = SaturationConfig::default();
    c.max_staleness_hours = 0;
    let v = c.validate();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].field, "max_staleness_hours");
}

#[test]
fn config_multiple_violations() {
    let mut c = SaturationConfig::default();
    c.saturation_threshold_millionths = MILLION + 1;
    c.min_observations = 0;
    c.velocity_window = 0;
    c.max_staleness_hours = 0;
    c.ratchet_widening_ceiling_millionths = MILLION + 1;
    let v = c.validate();
    assert_eq!(v.len(), 5);
}

#[test]
fn config_serde_roundtrip() {
    let c = SaturationConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: SaturationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn config_violation_serde_roundtrip() {
    let v = ConfigViolation {
        field: "test_field".into(),
        message: "must be positive".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ConfigViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ---------------------------------------------------------------------------
// SaturationReason
// ---------------------------------------------------------------------------

#[test]
fn saturation_reason_display_low_dm() {
    let r = SaturationReason::LowDarkMatterWithPositiveBurndown;
    let s = r.to_string();
    assert!(s.contains("low dark matter"));
}

#[test]
fn saturation_reason_display_high_dm() {
    let r = SaturationReason::HighDarkMatterFraction {
        fraction_millionths: 300_000,
    };
    assert!(r.to_string().contains("300000"));
}

#[test]
fn saturation_reason_display_negative_burndown() {
    let r = SaturationReason::NegativeBurndown {
        velocity_millionths: 50_000,
    };
    assert!(r.to_string().contains("50000"));
}

#[test]
fn saturation_reason_display_insufficient_velocity() {
    let r = SaturationReason::InsufficientBurndownVelocity {
        velocity_millionths: 1_000,
    };
    assert!(r.to_string().contains("1000"));
}

#[test]
fn saturation_reason_display_insufficient_observations() {
    let r = SaturationReason::InsufficientObservations {
        count: 3,
        required: 10,
    };
    let s = r.to_string();
    assert!(s.contains("3"));
    assert!(s.contains("10"));
}

#[test]
fn saturation_reason_display_stale_board() {
    let r = SaturationReason::StaleBoard {
        hours_since_refresh: 200,
    };
    assert!(r.to_string().contains("200"));
}

#[test]
fn saturation_reason_display_invalid_config() {
    let r = SaturationReason::InvalidConfiguration {
        violations: vec![ConfigViolation {
            field: "x".into(),
            message: "bad".into(),
        }],
    };
    assert!(r.to_string().contains("1 violations"));
}

#[test]
fn saturation_reason_serde_all_variants() {
    let variants: Vec<SaturationReason> = vec![
        SaturationReason::LowDarkMatterWithPositiveBurndown,
        SaturationReason::HighDarkMatterFraction { fraction_millionths: 300_000 },
        SaturationReason::NegativeBurndown { velocity_millionths: 50_000 },
        SaturationReason::InsufficientBurndownVelocity { velocity_millionths: 1_000 },
        SaturationReason::InsufficientObservations { count: 3, required: 10 },
        SaturationReason::StaleBoard { hours_since_refresh: 200 },
        SaturationReason::InvalidConfiguration {
            violations: vec![ConfigViolation { field: "x".into(), message: "bad".into() }],
        },
    ];
    for r in &variants {
        let json = serde_json::to_string(r).unwrap();
        let back: SaturationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// FreshnessReason
// ---------------------------------------------------------------------------

#[test]
fn freshness_reason_display_all() {
    assert_eq!(FreshnessReason::WithinWindow.to_string(), "within_window");
    assert_eq!(FreshnessReason::NoObservations.to_string(), "no_observations");
    let r = FreshnessReason::ExceedsWindow { hours_over: 24 };
    assert!(r.to_string().contains("24"));
}

#[test]
fn freshness_reason_serde_all_variants() {
    let variants: Vec<FreshnessReason> = vec![
        FreshnessReason::WithinWindow,
        FreshnessReason::ExceedsWindow { hours_over: 72 },
        FreshnessReason::NoObservations,
    ];
    for r in &variants {
        let json = serde_json::to_string(r).unwrap();
        let back: FreshnessReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// RatchetWideningReason
// ---------------------------------------------------------------------------

#[test]
fn ratchet_widening_reason_display_all() {
    assert_eq!(RatchetWideningReason::BelowCeiling.to_string(), "below_ceiling");
    assert_eq!(RatchetWideningReason::BoardStale.to_string(), "board_stale");
    assert_eq!(RatchetWideningReason::InsufficientData.to_string(), "insufficient_data");
    let r = RatchetWideningReason::AboveCeiling { excess_millionths: 50_000 };
    assert!(r.to_string().contains("50000"));
}

#[test]
fn ratchet_widening_reason_serde_all_variants() {
    let variants: Vec<RatchetWideningReason> = vec![
        RatchetWideningReason::BelowCeiling,
        RatchetWideningReason::AboveCeiling { excess_millionths: 50_000 },
        RatchetWideningReason::BoardStale,
        RatchetWideningReason::InsufficientData,
    ];
    for r in &variants {
        let json = serde_json::to_string(r).unwrap();
        let back: RatchetWideningReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// BoardSaturationVerdict
// ---------------------------------------------------------------------------

#[test]
fn saturation_verdict_content_hash_deterministic() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v1 = eval.evaluate_saturation(1500);
    let v2 = eval.evaluate_saturation(1500);
    assert_eq!(v1.content_hash(), v2.content_hash());
}

#[test]
fn saturation_verdict_display_contains_state() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_saturation(1500);
    let s = v.to_string();
    assert!(s.contains("saturation_verdict"));
}

#[test]
fn saturation_verdict_serde_roundtrip() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_saturation(1500);
    let json = serde_json::to_string(&v).unwrap();
    let back: BoardSaturationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back.state, v.state);
    assert_eq!(back.content_hash(), v.content_hash());
}

// ---------------------------------------------------------------------------
// FreshnessVerdict
// ---------------------------------------------------------------------------

#[test]
fn freshness_verdict_content_hash_deterministic() {
    let config = SaturationConfig::default();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v1 = eval.evaluate_freshness(1500);
    let v2 = eval.evaluate_freshness(1500);
    assert_eq!(v1.content_hash(), v2.content_hash());
}

#[test]
fn freshness_verdict_display_fresh() {
    let config = SaturationConfig::default();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_freshness(1500);
    let s = v.to_string();
    assert!(s.contains("fresh"));
}

#[test]
fn freshness_verdict_display_stale() {
    let mut config = SaturationConfig::default();
    config.max_staleness_hours = 1;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_freshness(1_000_000);
    let s = v.to_string();
    assert!(s.contains("stale"));
}

#[test]
fn freshness_verdict_serde_roundtrip() {
    let config = SaturationConfig::default();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_freshness(1500);
    let json = serde_json::to_string(&v).unwrap();
    let back: FreshnessVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ---------------------------------------------------------------------------
// RatchetWideningVerdict
// ---------------------------------------------------------------------------

#[test]
fn ratchet_verdict_content_hash_deterministic() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v1 = eval.evaluate_ratchet_widening(1500);
    let v2 = eval.evaluate_ratchet_widening(1500);
    assert_eq!(v1.content_hash(), v2.content_hash());
}

#[test]
fn ratchet_verdict_display_permitted() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_ratchet_widening(1500);
    let s = v.to_string();
    assert!(s.contains("ratchet_widening"));
    assert!(s.contains("permitted"));
}

#[test]
fn ratchet_verdict_display_blocked() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.ratchet_widening_ceiling_millionths = 50_000; // 5%, below our 10% dm
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_ratchet_widening(1500);
    let s = v.to_string();
    assert!(s.contains("blocked"));
}

#[test]
fn ratchet_verdict_serde_roundtrip() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_ratchet_widening(1500);
    let json = serde_json::to_string(&v).unwrap();
    let back: RatchetWideningVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ---------------------------------------------------------------------------
// SaturationGateEvaluator — saturation evaluation
// ---------------------------------------------------------------------------

#[test]
fn evaluator_saturated_low_dm_positive_burndown() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::Saturated);
    assert!(verdict.reasons.iter().any(|r| matches!(
        r,
        SaturationReason::LowDarkMatterWithPositiveBurndown
    )));
}

#[test]
fn evaluator_scope_limited_high_dm() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    let obs = build_observations(5, 1000, 100, 500_000, 5_000, 15_000);
    let eval = build_evaluator(500_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(verdict.reasons.iter().any(|r| matches!(
        r,
        SaturationReason::HighDarkMatterFraction { .. }
    )));
}

#[test]
fn evaluator_scope_limited_negative_burndown() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    let obs = build_observations(5, 1000, 100, 100_000, 20_000, 5_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(verdict.reasons.iter().any(|r| matches!(
        r,
        SaturationReason::NegativeBurndown { .. }
    )));
}

#[test]
fn evaluator_scope_limited_insufficient_observations() {
    let mut config = SaturationConfig::default();
    config.min_observations = 20;
    let obs = build_observations(3, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(verdict.reasons.iter().any(|r| matches!(
        r,
        SaturationReason::InsufficientObservations { .. }
    )));
}

#[test]
fn evaluator_scope_limited_invalid_config() {
    let mut config = SaturationConfig::default();
    config.min_observations = 0; // invalid
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(verdict.reasons.iter().any(|r| matches!(
        r,
        SaturationReason::InvalidConfiguration { .. }
    )));
}

#[test]
fn evaluator_scope_limited_insufficient_velocity() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.min_burndown_velocity_millionths = 999_999_999; // impossibly high
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(verdict.reasons.iter().any(|r| matches!(
        r,
        SaturationReason::InsufficientBurndownVelocity { .. }
    )));
}

// ---------------------------------------------------------------------------
// SaturationGateEvaluator — freshness evaluation
// ---------------------------------------------------------------------------

#[test]
fn evaluator_fresh_board() {
    let config = SaturationConfig::default(); // max_staleness_hours = 168
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_freshness(1500);
    assert!(verdict.is_fresh);
    assert!(matches!(verdict.reason, FreshnessReason::WithinWindow));
}

#[test]
fn evaluator_stale_board() {
    let mut config = SaturationConfig::default();
    config.max_staleness_hours = 1; // 3600 seconds
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    // Last obs at 1400. now = 1400 + 7200 = 8600
    let verdict = eval.evaluate_freshness(8600);
    assert!(!verdict.is_fresh);
    assert!(matches!(verdict.reason, FreshnessReason::ExceedsWindow { .. }));
}

#[test]
fn evaluator_no_observations_means_stale() {
    let config = SaturationConfig::default();
    let eval = build_evaluator(0, MILLION, vec![], config);
    let verdict = eval.evaluate_freshness(5000);
    assert!(!verdict.is_fresh);
    assert!(matches!(verdict.reason, FreshnessReason::NoObservations));
    assert_eq!(verdict.hours_since_last_observation, u64::MAX);
}

// ---------------------------------------------------------------------------
// SaturationGateEvaluator — ratchet widening evaluation
// ---------------------------------------------------------------------------

#[test]
fn ratchet_widening_permitted_low_dm() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.ratchet_widening_ceiling_millionths = 200_000;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(verdict.permitted);
    assert!(matches!(verdict.reason, RatchetWideningReason::BelowCeiling));
}

#[test]
fn ratchet_widening_blocked_high_dm() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.ratchet_widening_ceiling_millionths = 50_000; // 5%
    let obs = build_observations(5, 1000, 100, 300_000, 5_000, 15_000);
    let eval = build_evaluator(300_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(!verdict.permitted);
    assert!(matches!(verdict.reason, RatchetWideningReason::AboveCeiling { .. }));
}

#[test]
fn ratchet_widening_blocked_stale() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.max_staleness_hours = 1;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1_000_000);
    assert!(!verdict.permitted);
    assert!(matches!(verdict.reason, RatchetWideningReason::BoardStale));
}

#[test]
fn ratchet_widening_blocked_insufficient_data() {
    let mut config = SaturationConfig::default();
    config.min_observations = 20;
    let obs = build_observations(3, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(!verdict.permitted);
    assert!(matches!(verdict.reason, RatchetWideningReason::InsufficientData));
}

// ---------------------------------------------------------------------------
// Full pipeline (evaluate)
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_saturated() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    assert_eq!(receipt.composite_state, BoardState::Saturated);
    assert_eq!(receipt.schema_version, DARK_MATTER_GATE_SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn full_pipeline_scope_limited() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    let obs = build_observations(5, 1000, 100, 500_000, 5_000, 15_000);
    let eval = build_evaluator(500_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    assert_eq!(receipt.composite_state, BoardState::ScopeLimited);
}

#[test]
fn full_pipeline_stale_overrides_saturation() {
    let mut config = low_dm_config();
    config.max_staleness_hours = 1;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    // Would be saturated if fresh, but now is far in the future
    let receipt = eval.evaluate(1_000_000);
    assert_eq!(receipt.composite_state, BoardState::Stale);
}

#[test]
fn full_pipeline_receipt_hash_deterministic() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let r1 = eval.evaluate(1500);
    let r2 = eval.evaluate(1500);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn full_pipeline_receipt_hash_differs_on_time() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let r1 = eval.evaluate(1500);
    let r2 = eval.evaluate(1501);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn full_pipeline_receipt_display() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    let s = receipt.to_string();
    assert!(s.contains("receipt"));
}

#[test]
fn full_pipeline_receipt_serde_roundtrip() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.composite_state, receipt.composite_state);
    assert_eq!(back.receipt_hash, receipt.receipt_hash);
}

#[test]
fn decision_receipt_compute_hash_is_deterministic() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let sat = eval.evaluate_saturation(1500);
    let fresh = eval.evaluate_freshness(1500);
    let ratchet = eval.evaluate_ratchet_widening(1500);
    let h1 = DecisionReceipt::compute_hash(&sat, &fresh, &ratchet, epoch(), 1500);
    let h2 = DecisionReceipt::compute_hash(&sat, &fresh, &ratchet, epoch(), 1500);
    assert_eq!(h1, h2);
}

#[test]
fn decision_receipt_compute_hash_differs_on_epoch() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let sat = eval.evaluate_saturation(1500);
    let fresh = eval.evaluate_freshness(1500);
    let ratchet = eval.evaluate_ratchet_widening(1500);
    let h1 = DecisionReceipt::compute_hash(&sat, &fresh, &ratchet, SecurityEpoch::from_raw(1), 1500);
    let h2 = DecisionReceipt::compute_hash(&sat, &fresh, &ratchet, SecurityEpoch::from_raw(2), 1500);
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Evidence emission
// ---------------------------------------------------------------------------

#[test]
fn evidence_emitted_correctly() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    assert_eq!(evidence.schema_version, DARK_MATTER_GATE_SCHEMA_VERSION);
    assert_eq!(evidence.bead_id, DARK_MATTER_GATE_BEAD_ID);
    assert_eq!(evidence.component, COMPONENT);
    assert_eq!(evidence.board_state, BoardState::Saturated);
}

#[test]
fn evidence_estimate_summary_fields() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    let summary = &evidence.estimate_summary;
    assert_eq!(summary.total_surface_millionths, MILLION);
    assert_eq!(summary.active_mass_millionths, 100_000);
    assert_eq!(summary.active_region_count, 1);
    assert_eq!(summary.retired_region_count, 0);
    assert_eq!(summary.fraction_millionths, 100_000); // 10%
}

#[test]
fn evidence_burndown_metrics_fields() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    let metrics = &evidence.burndown_metrics;
    assert_eq!(metrics.observation_count, 5);
    assert!(metrics.time_span_secs > 0);
    assert!(metrics.retirement_velocity_millionths > 0);
}

#[test]
fn evidence_stale_board_state() {
    let mut config = low_dm_config();
    config.max_staleness_hours = 1;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1_000_000);
    assert_eq!(evidence.board_state, BoardState::Stale);
}

#[test]
fn evidence_content_hash_deterministic() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let e1 = eval.emit_evidence(1500);
    let e2 = eval.emit_evidence(1500);
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn evidence_content_hash_differs_on_time() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let e1 = eval.emit_evidence(1500);
    let e2 = eval.emit_evidence(1501);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn evidence_display_contains_key_fields() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    let s = evidence.to_string();
    assert!(s.contains("dark_matter_evidence"));
}

#[test]
fn evidence_serde_roundtrip() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    let json = serde_json::to_string(&evidence).unwrap();
    let back: DarkMatterEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back.board_state, evidence.board_state);
    assert_eq!(back.receipt_hash, evidence.receipt_hash);
}

#[test]
fn evidence_mass_by_kind_populated() {
    let ep = epoch();
    let mut estimate = DarkMatterEstimate::new(MILLION, ep, 1000);
    estimate.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 60_000, false));
    estimate.add_region(make_region("r2", DarkMatterRegionKind::UnverifiedInterleaving, 40_000, false));
    let mut config = low_dm_config();
    config.min_burndown_velocity_millionths = 0;
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let mut tracker = BurndownTracker::new(MILLION, ep);
    for o in obs {
        tracker.record(o);
    }
    let eval = SaturationGateEvaluator::new(config, estimate, tracker);
    let evidence = eval.emit_evidence(1500);
    assert!(evidence.estimate_summary.mass_by_kind.contains_key("untested_code_path"));
    assert!(evidence.estimate_summary.mass_by_kind.contains_key("unverified_interleaving"));
}

// ---------------------------------------------------------------------------
// SaturationGateEvaluator — serde
// ---------------------------------------------------------------------------

#[test]
fn evaluator_serde_roundtrip() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let json = serde_json::to_string(&eval).unwrap();
    let back: SaturationGateEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(back.config, eval.config);
    assert_eq!(back.estimate, eval.estimate);
    assert_eq!(back.tracker, eval.tracker);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn zero_active_mass_is_saturated() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.min_burndown_velocity_millionths = 0;
    // 0 active mass => 0% dark matter
    let obs = build_observations(5, 1000, 100, 0, 0, 0);
    let eval = build_evaluator(0, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(1500);
    assert_eq!(verdict.state, BoardState::Saturated);
    assert_eq!(verdict.dark_matter_fraction_millionths, 0);
}

#[test]
fn boundary_at_saturation_threshold() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.saturation_threshold_millionths = 200_000;
    config.min_burndown_velocity_millionths = 0;
    // Exactly at threshold: 200_000/1_000_000 = 20%
    let obs = build_observations(5, 1000, 100, 200_000, 0, 5_000);
    let eval = build_evaluator(200_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(1500);
    // fraction = 200_000 <= threshold of 200_000 => ok (and velocity >= 0 req)
    assert_eq!(verdict.state, BoardState::Saturated);
}

#[test]
fn boundary_one_above_saturation_threshold() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.saturation_threshold_millionths = 199_999;
    config.min_burndown_velocity_millionths = 0;
    let obs = build_observations(5, 1000, 100, 200_000, 0, 5_000);
    let eval = build_evaluator(200_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(1500);
    // fraction = 200_000 > threshold of 199_999 => scope limited
    assert_eq!(verdict.state, BoardState::ScopeLimited);
}

#[test]
fn evaluator_with_multiple_regions_mixed_retired() {
    let ep = epoch();
    let mut estimate = DarkMatterEstimate::new(MILLION, ep, 1000);
    estimate.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 50_000, false));
    estimate.add_region(make_region("r2", DarkMatterRegionKind::UnverifiedInterleaving, 30_000, false));
    estimate.add_region(make_region("r3", DarkMatterRegionKind::UntestedErrorRecovery, 20_000, true));
    let mut config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 80_000, 5_000, 15_000);
    let mut tracker = BurndownTracker::new(MILLION, ep);
    for o in obs {
        tracker.record(o);
    }
    let eval = SaturationGateEvaluator::new(config, estimate, tracker);
    let receipt = eval.evaluate(1500);
    // 80_000 / 1_000_000 = 8% < 20% threshold
    assert_eq!(receipt.composite_state, BoardState::Saturated);
}

#[test]
fn estimate_summary_serde_roundtrip() {
    let summary = EstimateSummary {
        total_surface_millionths: MILLION,
        active_mass_millionths: 100_000,
        retired_mass_millionths: 50_000,
        fraction_millionths: 100_000,
        active_region_count: 2,
        retired_region_count: 1,
        mass_by_kind: {
            let mut m = BTreeMap::new();
            m.insert("untested_code_path".to_string(), 80_000u64);
            m
        },
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: EstimateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

#[test]
fn burndown_metrics_serde_roundtrip() {
    let metrics = BurndownMetrics {
        discovery_velocity_millionths: 1000,
        retirement_velocity_millionths: 2000,
        net_velocity_millionths: 1000,
        observation_count: 5,
        time_span_secs: 400,
        hours_since_last_observation: 0,
    };
    let json = serde_json::to_string(&metrics).unwrap();
    let back: BurndownMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(back, metrics);
}

#[test]
fn full_pipeline_no_observations_yields_stale() {
    let config = SaturationConfig::default();
    let eval = build_evaluator(0, MILLION, vec![], config);
    let receipt = eval.evaluate(5000);
    // No observations => freshness check says stale => composite = Stale
    assert_eq!(receipt.composite_state, BoardState::Stale);
}

#[test]
fn evidence_no_observations_has_max_hours_since() {
    let config = SaturationConfig::default();
    let eval = build_evaluator(0, MILLION, vec![], config);
    let evidence = eval.emit_evidence(5000);
    assert_eq!(evidence.burndown_metrics.hours_since_last_observation, u64::MAX);
}

#[test]
fn region_with_zero_mass_contributes_nothing() {
    let mut e = DarkMatterEstimate::new(MILLION, epoch(), 1000);
    e.add_region(make_region("r1", DarkMatterRegionKind::UntestedCodePath, 0, false));
    assert_eq!(e.active_mass(), 0);
    assert_eq!(e.effective_mass(), 0);
    assert_eq!(e.dark_matter_fraction(), 0);
    assert_eq!(e.active_region_count(), 1); // still counted
}

#[test]
fn saturation_verdict_carries_epoch_and_timestamp() {
    let config = low_dm_config();
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(9999);
    assert_eq!(verdict.epoch, epoch());
    assert_eq!(verdict.verdict_at_epoch_secs, 9999);
}

#[test]
fn ratchet_widening_at_ceiling_boundary_is_permitted() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.ratchet_widening_ceiling_millionths = 100_000; // 10%
    // Active mass = 100_000 => fraction = 100_000 <= ceiling 100_000
    let obs = build_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = build_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(verdict.permitted);
}

#[test]
fn ratchet_widening_above_ceiling_has_correct_excess() {
    let mut config = SaturationConfig::default();
    config.min_observations = 3;
    config.ratchet_widening_ceiling_millionths = 50_000; // 5%
    // Active mass = 200_000 => fraction = 200_000. excess = 200_000 - 50_000 = 150_000
    let obs = build_observations(5, 1000, 100, 200_000, 5_000, 15_000);
    let eval = build_evaluator(200_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(!verdict.permitted);
    if let RatchetWideningReason::AboveCeiling { excess_millionths } = verdict.reason {
        assert_eq!(excess_millionths, 150_000);
    } else {
        panic!("expected AboveCeiling reason");
    }
}
