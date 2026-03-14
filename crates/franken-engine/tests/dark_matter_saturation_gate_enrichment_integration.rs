//! Integration enrichment tests for `dark_matter_saturation_gate`.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, Default coverage, constants, region computation,
//! estimate aggregation, burndown tracking, board state, config validation,
//! evaluator pipelines, freshness, ratchet widening, decision receipts,
//! evidence emission, and JSON field-name stability.

use std::collections::BTreeSet;

use frankenengine_engine::dark_matter_saturation_gate::{
    BoardSaturationVerdict, BoardState, BurndownObservation, BurndownTracker, COMPONENT,
    ConfigViolation, DARK_MATTER_GATE_BEAD_ID, DARK_MATTER_GATE_SCHEMA_VERSION,
    DEFAULT_MAX_STALENESS_HOURS, DEFAULT_MIN_BURNDOWN_VELOCITY, DEFAULT_MIN_OBSERVATIONS,
    DEFAULT_RATCHET_WIDENING_CEILING, DEFAULT_SATURATION_THRESHOLD, DarkMatterEstimate,
    DarkMatterEvidence, DarkMatterRegion, DarkMatterRegionKind, DecisionReceipt, FreshnessReason,
    FreshnessVerdict, RatchetWideningReason, RatchetWideningVerdict, SaturationConfig,
    SaturationGateEvaluator, SaturationReason,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_region(id: &str, kind: DarkMatterRegionKind, mass: u64, retired: bool) -> DarkMatterRegion {
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

fn make_observations(
    count: usize,
    start: u64,
    interval: u64,
    initial_active: u64,
    discovery: u64,
    retirement: u64,
) -> Vec<BurndownObservation> {
    let mut obs = Vec::with_capacity(count);
    let mut cum_disc = 0u64;
    let mut cum_ret = 0u64;
    let mut active = initial_active;
    for i in 0..count {
        obs.push(BurndownObservation {
            timestamp_epoch_secs: start + (i as u64) * interval,
            active_mass_millionths: active,
            cumulative_discovered_millionths: cum_disc,
            cumulative_retired_millionths: cum_ret,
        });
        cum_disc = cum_disc.saturating_add(discovery);
        cum_ret = cum_ret.saturating_add(retirement);
        active = active.saturating_add(discovery).saturating_sub(retirement);
    }
    obs
}

fn make_evaluator(
    active_mass: u64,
    total_surface: u64,
    observations: Vec<BurndownObservation>,
    config: SaturationConfig,
) -> SaturationGateEvaluator {
    let epoch = SecurityEpoch::from_raw(1);
    let mut estimate = DarkMatterEstimate::new(total_surface, epoch, 1000);
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
    let mut tracker = BurndownTracker::new(total_surface, epoch);
    for obs in observations {
        tracker.record(obs);
    }
    SaturationGateEvaluator::new(config, estimate, tracker)
}

// ===========================================================================
// Copy semantics
// ===========================================================================

#[test]
fn enrichment_region_kind_copy_semantics() {
    let a = DarkMatterRegionKind::UntestedCodePath;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_board_state_copy_semantics() {
    let a = BoardState::Saturated;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_freshness_reason_copy_via_clone() {
    let a = FreshnessReason::WithinWindow;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_ratchet_reason_copy_via_clone() {
    let a = RatchetWideningReason::BelowCeiling;
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn enrichment_region_clone_independence() {
    let a = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let mut b = a.clone();
    b.mass_millionths = 200_000;
    assert_eq!(a.mass_millionths, 100_000);
    assert_eq!(b.mass_millionths, 200_000);
}

#[test]
fn enrichment_config_clone_independence() {
    let a = SaturationConfig::default();
    let mut b = a.clone();
    b.min_observations = 999;
    assert_eq!(a.min_observations, DEFAULT_MIN_OBSERVATIONS);
    assert_eq!(b.min_observations, 999);
}

#[test]
fn enrichment_estimate_clone_independence() {
    let mut a = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    a.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        false,
    ));
    let b = a.clone();
    a.add_region(make_region(
        "r2",
        DarkMatterRegionKind::UnverifiedInterleaving,
        50_000,
        false,
    ));
    assert_eq!(a.total_region_count(), 2);
    assert_eq!(b.total_region_count(), 1);
}

#[test]
fn enrichment_tracker_clone_independence() {
    let mut a = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    a.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 300_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    let b = a.clone();
    a.record(BurndownObservation {
        timestamp_epoch_secs: 200,
        active_mass_millionths: 250_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 50_000,
    });
    assert_eq!(a.observation_count(), 2);
    assert_eq!(b.observation_count(), 1);
}

// ===========================================================================
// BTreeSet ordering
// ===========================================================================

#[test]
fn enrichment_region_kind_btreeset_ordering() {
    let mut set = BTreeSet::new();
    for &kind in DarkMatterRegionKind::ALL {
        set.insert(kind.as_str().to_string());
    }
    assert_eq!(set.len(), DarkMatterRegionKind::ALL.len());
}

#[test]
fn enrichment_board_state_btreeset_ordering() {
    let mut set = BTreeSet::new();
    for &state in BoardState::ALL {
        set.insert(state.as_str().to_string());
    }
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_content_hash_btreeset_ordering() {
    let r1 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r2", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    let mut set = BTreeSet::new();
    set.insert(r1.content_hash());
    set.insert(r2.content_hash());
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_region_kind_serde_all_variants() {
    for &kind in DarkMatterRegionKind::ALL {
        let json = serde_json::to_string(&kind).unwrap();
        let back: DarkMatterRegionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

#[test]
fn enrichment_board_state_serde_all_variants() {
    for &state in BoardState::ALL {
        let json = serde_json::to_string(&state).unwrap();
        let back: BoardState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}

#[test]
fn enrichment_region_serde_roundtrip() {
    let r = make_region(
        "gc_reentry",
        DarkMatterRegionKind::UnobservedInteraction,
        50_000,
        false,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: DarkMatterRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn enrichment_region_retired_serde_roundtrip() {
    let r = make_region(
        "retired_r",
        DarkMatterRegionKind::UntestedErrorRecovery,
        75_000,
        true,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: DarkMatterRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
    assert!(back.retired);
}

#[test]
fn enrichment_observation_serde_roundtrip() {
    let obs = BurndownObservation {
        timestamp_epoch_secs: 5000,
        active_mass_millionths: 300_000,
        cumulative_discovered_millionths: 100_000,
        cumulative_retired_millionths: 50_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: BurndownObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, obs);
}

#[test]
fn enrichment_estimate_serde_roundtrip() {
    let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    e.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        false,
    ));
    e.add_region(make_region(
        "r2",
        DarkMatterRegionKind::UnverifiedInterleaving,
        30_000,
        true,
    ));
    let json = serde_json::to_string(&e).unwrap();
    let back: DarkMatterEstimate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn enrichment_tracker_serde_roundtrip() {
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    for obs in make_observations(5, 1000, 100, 300_000, 5_000, 10_000) {
        t.record(obs);
    }
    let json = serde_json::to_string(&t).unwrap();
    let back: BurndownTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let c = SaturationConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: SaturationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn enrichment_config_violation_serde_roundtrip() {
    let v = ConfigViolation {
        field: "min_observations".to_string(),
        message: "must be > 0".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ConfigViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_freshness_verdict_serde_roundtrip() {
    let v = FreshnessVerdict {
        is_fresh: true,
        hours_since_last_observation: 2,
        max_staleness_hours: 168,
        reason: FreshnessReason::WithinWindow,
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 5000,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: FreshnessVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_ratchet_verdict_serde_roundtrip() {
    let v = RatchetWideningVerdict {
        permitted: false,
        dark_matter_fraction_millionths: 300_000,
        ceiling_millionths: 150_000,
        reason: RatchetWideningReason::AboveCeiling {
            excess_millionths: 150_000,
        },
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 5000,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: RatchetWideningVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_saturation_verdict_serde_roundtrip() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let v = eval.evaluate_saturation(1500);
    let json = serde_json::to_string(&v).unwrap();
    let back: BoardSaturationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back.state, v.state);
    assert_eq!(
        back.dark_matter_fraction_millionths,
        v.dark_matter_fraction_millionths
    );
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.receipt_hash, receipt.receipt_hash);
    assert_eq!(back.composite_state, receipt.composite_state);
}

#[test]
fn enrichment_evidence_serde_roundtrip() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    let json = serde_json::to_string(&evidence).unwrap();
    let back: DarkMatterEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back.board_state, evidence.board_state);
    assert_eq!(back.receipt_hash, evidence.receipt_hash);
}

#[test]
fn enrichment_evaluator_serde_roundtrip() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let json = serde_json::to_string(&eval).unwrap();
    let back: SaturationGateEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(back.config, eval.config);
    assert_eq!(back.estimate, eval.estimate);
    assert_eq!(back.tracker, eval.tracker);
}

#[test]
fn enrichment_freshness_reason_serde_all_variants() {
    let variants: Vec<FreshnessReason> = vec![
        FreshnessReason::WithinWindow,
        FreshnessReason::ExceedsWindow { hours_over: 24 },
        FreshnessReason::NoObservations,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: FreshnessReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn enrichment_ratchet_reason_serde_all_variants() {
    let variants: Vec<RatchetWideningReason> = vec![
        RatchetWideningReason::BelowCeiling,
        RatchetWideningReason::AboveCeiling {
            excess_millionths: 50_000,
        },
        RatchetWideningReason::BoardStale,
        RatchetWideningReason::InsufficientData,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: RatchetWideningReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ===========================================================================
// Display coverage
// ===========================================================================

#[test]
fn enrichment_region_kind_display_all_variants() {
    for &kind in DarkMatterRegionKind::ALL {
        let s = kind.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, kind.as_str());
    }
}

#[test]
fn enrichment_board_state_display_all_variants() {
    for &state in BoardState::ALL {
        let s = state.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, state.as_str());
    }
}

#[test]
fn enrichment_region_display_active() {
    let r = make_region(
        "gc_reentry",
        DarkMatterRegionKind::UnobservedInteraction,
        50_000,
        false,
    );
    let s = r.to_string();
    assert!(s.contains("gc_reentry"));
    assert!(s.contains("active"));
}

#[test]
fn enrichment_region_display_retired() {
    let r = make_region(
        "old_path",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        true,
    );
    let s = r.to_string();
    assert!(s.contains("old_path"));
    assert!(s.contains("retired"));
}

#[test]
fn enrichment_estimate_display() {
    let e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    let s = e.to_string();
    assert!(s.contains("dark_matter_estimate"));
}

#[test]
fn enrichment_tracker_display() {
    let t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    let s = t.to_string();
    assert!(s.contains("burndown"));
}

#[test]
fn enrichment_freshness_verdict_display_fresh() {
    let v = FreshnessVerdict {
        is_fresh: true,
        hours_since_last_observation: 2,
        max_staleness_hours: 168,
        reason: FreshnessReason::WithinWindow,
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 5000,
    };
    let s = v.to_string();
    assert!(s.contains("fresh"));
    assert!(s.contains("2h"));
}

#[test]
fn enrichment_freshness_verdict_display_stale() {
    let v = FreshnessVerdict {
        is_fresh: false,
        hours_since_last_observation: 200,
        max_staleness_hours: 168,
        reason: FreshnessReason::ExceedsWindow { hours_over: 32 },
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 5000,
    };
    let s = v.to_string();
    assert!(s.contains("stale"));
    assert!(s.contains("200h"));
}

#[test]
fn enrichment_ratchet_verdict_display_permitted() {
    let v = RatchetWideningVerdict {
        permitted: true,
        dark_matter_fraction_millionths: 100_000,
        ceiling_millionths: 150_000,
        reason: RatchetWideningReason::BelowCeiling,
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 5000,
    };
    let s = v.to_string();
    assert!(s.contains("permitted"));
    assert!(s.contains("100000"));
}

#[test]
fn enrichment_ratchet_verdict_display_blocked() {
    let v = RatchetWideningVerdict {
        permitted: false,
        dark_matter_fraction_millionths: 300_000,
        ceiling_millionths: 150_000,
        reason: RatchetWideningReason::AboveCeiling {
            excess_millionths: 150_000,
        },
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 5000,
    };
    let s = v.to_string();
    assert!(s.contains("blocked"));
}

#[test]
fn enrichment_freshness_reason_display_all() {
    assert_eq!(FreshnessReason::WithinWindow.to_string(), "within_window");
    assert_eq!(
        FreshnessReason::NoObservations.to_string(),
        "no_observations"
    );
    let ex = FreshnessReason::ExceedsWindow { hours_over: 48 };
    assert!(ex.to_string().contains("48"));
}

#[test]
fn enrichment_ratchet_reason_display_all() {
    assert_eq!(
        RatchetWideningReason::BelowCeiling.to_string(),
        "below_ceiling"
    );
    assert_eq!(RatchetWideningReason::BoardStale.to_string(), "board_stale");
    assert_eq!(
        RatchetWideningReason::InsufficientData.to_string(),
        "insufficient_data"
    );
    let ab = RatchetWideningReason::AboveCeiling {
        excess_millionths: 75_000,
    };
    assert!(ab.to_string().contains("75000"));
}

#[test]
fn enrichment_saturation_reason_display_all() {
    let high_dm = SaturationReason::HighDarkMatterFraction {
        fraction_millionths: 400_000,
    };
    assert!(high_dm.to_string().contains("400000"));

    let neg = SaturationReason::NegativeBurndown {
        velocity_millionths: 50_000,
    };
    assert!(neg.to_string().contains("50000"));

    let insuff_vel = SaturationReason::InsufficientBurndownVelocity {
        velocity_millionths: 10_000,
    };
    assert!(insuff_vel.to_string().contains("10000"));

    let insuff_obs = SaturationReason::InsufficientObservations {
        count: 3,
        required: 10,
    };
    let s = insuff_obs.to_string();
    assert!(s.contains('3') || s.contains("10"));

    let low_dm = SaturationReason::LowDarkMatterWithPositiveBurndown;
    assert!(!low_dm.to_string().is_empty());
}

#[test]
fn enrichment_evidence_display() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    let s = evidence.to_string();
    assert!(s.contains("dark_matter_evidence"));
}

#[test]
fn enrichment_receipt_display() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    let s = receipt.to_string();
    assert!(s.contains("receipt"));
}

// ===========================================================================
// std::error::Error
// ===========================================================================

#[test]
fn enrichment_saturation_reason_display_nonempty() {
    let reasons: Vec<SaturationReason> = vec![
        SaturationReason::HighDarkMatterFraction {
            fraction_millionths: 500_000,
        },
        SaturationReason::NegativeBurndown {
            velocity_millionths: 10_000,
        },
        SaturationReason::InsufficientBurndownVelocity {
            velocity_millionths: 5_000,
        },
        SaturationReason::InsufficientObservations {
            count: 2,
            required: 10,
        },
        SaturationReason::LowDarkMatterWithPositiveBurndown,
        SaturationReason::InvalidConfiguration {
            violations: vec![ConfigViolation {
                field: "min_observations".to_string(),
                message: "must be > 0".to_string(),
            }],
        },
    ];
    for r in &reasons {
        assert!(!r.to_string().is_empty());
    }
}

// ===========================================================================
// Debug nonempty
// ===========================================================================

#[test]
fn enrichment_region_kind_debug() {
    for &kind in DarkMatterRegionKind::ALL {
        assert!(!format!("{kind:?}").is_empty());
    }
}

#[test]
fn enrichment_board_state_debug() {
    for &state in BoardState::ALL {
        assert!(!format!("{state:?}").is_empty());
    }
}

#[test]
fn enrichment_region_debug() {
    let r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    assert!(!format!("{r:?}").is_empty());
}

#[test]
fn enrichment_estimate_debug() {
    let e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    assert!(!format!("{e:?}").is_empty());
}

#[test]
fn enrichment_tracker_debug() {
    let t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    assert!(!format!("{t:?}").is_empty());
}

#[test]
fn enrichment_config_debug() {
    let c = SaturationConfig::default();
    assert!(!format!("{c:?}").is_empty());
}

#[test]
fn enrichment_evaluator_debug() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(3, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    assert!(!format!("{eval:?}").is_empty());
}

#[test]
fn enrichment_freshness_verdict_debug() {
    let v = FreshnessVerdict {
        is_fresh: true,
        hours_since_last_observation: 0,
        max_staleness_hours: 168,
        reason: FreshnessReason::WithinWindow,
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 1000,
    };
    assert!(!format!("{v:?}").is_empty());
}

#[test]
fn enrichment_ratchet_verdict_debug() {
    let v = RatchetWideningVerdict {
        permitted: true,
        dark_matter_fraction_millionths: 100_000,
        ceiling_millionths: 200_000,
        reason: RatchetWideningReason::BelowCeiling,
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 1000,
    };
    assert!(!format!("{v:?}").is_empty());
}

#[test]
fn enrichment_decision_receipt_debug() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    assert!(!format!("{receipt:?}").is_empty());
}

#[test]
fn enrichment_evidence_debug() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    assert!(!format!("{evidence:?}").is_empty());
}

// ===========================================================================
// Default coverage
// ===========================================================================

#[test]
fn enrichment_config_default_valid() {
    let config = SaturationConfig::default();
    assert!(config.validate().is_empty());
    assert_eq!(
        config.saturation_threshold_millionths,
        DEFAULT_SATURATION_THRESHOLD
    );
    assert_eq!(
        config.ratchet_widening_ceiling_millionths,
        DEFAULT_RATCHET_WIDENING_CEILING
    );
    assert_eq!(
        config.min_burndown_velocity_millionths,
        DEFAULT_MIN_BURNDOWN_VELOCITY
    );
    assert_eq!(config.min_observations, DEFAULT_MIN_OBSERVATIONS);
    assert_eq!(config.max_staleness_hours, DEFAULT_MAX_STALENESS_HOURS);
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_populated() {
    assert!(DARK_MATTER_GATE_SCHEMA_VERSION.contains("dark-matter"));
}

#[test]
fn enrichment_bead_id_populated() {
    assert!(DARK_MATTER_GATE_BEAD_ID.contains("bd-"));
}

#[test]
fn enrichment_component_populated() {
    assert!(COMPONENT.contains("dark_matter"));
}

#[test]
fn enrichment_default_threshold_values() {
    const { assert!(DEFAULT_SATURATION_THRESHOLD <= MILLION) };
    const { assert!(DEFAULT_RATCHET_WIDENING_CEILING <= MILLION) };
    const { assert!(DEFAULT_MIN_OBSERVATIONS > 0) };
    const { assert!(DEFAULT_MAX_STALENESS_HOURS > 0) };
}

// ===========================================================================
// Region computation
// ===========================================================================

#[test]
fn enrichment_region_effective_mass_active() {
    let r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    assert_eq!(r.effective_mass(), 100_000);
}

#[test]
fn enrichment_region_effective_mass_retired_is_zero() {
    let r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, true);
    assert_eq!(r.effective_mass(), 0);
}

#[test]
fn enrichment_region_effective_mass_weighted() {
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    r.priority_weight_millionths = 500_000;
    assert_eq!(r.effective_mass(), 100_000);
}

#[test]
fn enrichment_region_effective_mass_zero_weight() {
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    r.priority_weight_millionths = 0;
    assert_eq!(r.effective_mass(), 0);
}

#[test]
fn enrichment_region_content_hash_deterministic() {
    let r1 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_region_content_hash_varies_by_id() {
    let r1 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r2", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_region_content_hash_varies_by_kind() {
    let r1 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region(
        "r1",
        DarkMatterRegionKind::UnverifiedInterleaving,
        100_000,
        false,
    );
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_region_content_hash_varies_by_mass() {
    let r1 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_region_content_hash_varies_by_retired() {
    let r1 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let r2 = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, true);
    assert_ne!(r1.content_hash(), r2.content_hash());
}

// ===========================================================================
// Estimate aggregation
// ===========================================================================

#[test]
fn enrichment_estimate_empty() {
    let e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    assert_eq!(e.active_mass(), 0);
    assert_eq!(e.retired_mass(), 0);
    assert_eq!(e.dark_matter_fraction(), 0);
    assert_eq!(e.active_region_count(), 0);
    assert_eq!(e.retired_region_count(), 0);
    assert_eq!(e.total_region_count(), 0);
}

#[test]
fn enrichment_estimate_single_active() {
    let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    e.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        false,
    ));
    assert_eq!(e.active_mass(), 100_000);
    assert_eq!(e.retired_mass(), 0);
    assert_eq!(e.dark_matter_fraction(), 100_000);
    assert_eq!(e.active_region_count(), 1);
}

#[test]
fn enrichment_estimate_mixed_active_retired() {
    let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    e.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        false,
    ));
    e.add_region(make_region(
        "r2",
        DarkMatterRegionKind::UntestedCodePath,
        50_000,
        true,
    ));
    e.add_region(make_region(
        "r3",
        DarkMatterRegionKind::UnverifiedInterleaving,
        30_000,
        false,
    ));
    assert_eq!(e.active_mass(), 130_000);
    assert_eq!(e.retired_mass(), 50_000);
    assert_eq!(e.active_region_count(), 2);
    assert_eq!(e.retired_region_count(), 1);
    assert_eq!(e.total_region_count(), 3);
}

#[test]
fn enrichment_estimate_fraction_zero_surface() {
    let e = DarkMatterEstimate::new(0, SecurityEpoch::from_raw(1), 1000);
    assert_eq!(e.dark_matter_fraction(), MILLION);
}

#[test]
fn enrichment_estimate_effective_mass_with_weight() {
    let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    let mut r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
    r.priority_weight_millionths = 500_000;
    e.add_region(r);
    assert_eq!(e.effective_mass(), 100_000);
}

#[test]
fn enrichment_estimate_mass_by_kind() {
    let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    e.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        false,
    ));
    e.add_region(make_region(
        "r2",
        DarkMatterRegionKind::UntestedCodePath,
        50_000,
        true,
    ));
    e.add_region(make_region(
        "r3",
        DarkMatterRegionKind::UnverifiedInterleaving,
        30_000,
        false,
    ));
    let by_kind = e.mass_by_kind();
    assert_eq!(
        by_kind[&DarkMatterRegionKind::UntestedCodePath],
        (100_000, 50_000)
    );
    assert_eq!(
        by_kind[&DarkMatterRegionKind::UnverifiedInterleaving],
        (30_000, 0)
    );
}

#[test]
fn enrichment_estimate_add_region_overwrites_duplicate() {
    let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    e.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        false,
    ));
    e.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        200_000,
        false,
    ));
    assert_eq!(e.total_region_count(), 1);
    assert_eq!(e.active_mass(), 200_000);
}

#[test]
fn enrichment_estimate_content_hash_deterministic() {
    let build = || {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        e
    };
    assert_eq!(build().content_hash(), build().content_hash());
}

#[test]
fn enrichment_estimate_content_hash_varies() {
    let mut e1 = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    e1.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        100_000,
        false,
    ));
    let mut e2 = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
    e2.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        200_000,
        false,
    ));
    assert_ne!(e1.content_hash(), e2.content_hash());
}

// ===========================================================================
// Burndown tracking
// ===========================================================================

#[test]
fn enrichment_tracker_empty() {
    let t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    assert_eq!(t.observation_count(), 0);
    assert_eq!(t.latest_active_mass(), 0);
    assert_eq!(t.time_span_secs(), 0);
    assert!(!t.has_enough_observations(1));
}

#[test]
fn enrichment_tracker_single_observation() {
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    t.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 300_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    assert_eq!(t.observation_count(), 1);
    assert_eq!(t.latest_active_mass(), 300_000);
    assert!(t.has_enough_observations(1));
    assert_eq!(t.discovery_velocity(10), 0);
    assert_eq!(t.retirement_velocity(10), 0);
}

#[test]
fn enrichment_tracker_in_order() {
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    t.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 500_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    t.record(BurndownObservation {
        timestamp_epoch_secs: 200,
        active_mass_millionths: 400_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 100_000,
    });
    assert_eq!(t.observation_count(), 2);
    assert_eq!(t.latest_active_mass(), 400_000);
    assert_eq!(t.time_span_secs(), 100);
}

#[test]
fn enrichment_tracker_drops_out_of_order() {
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    t.record(BurndownObservation {
        timestamp_epoch_secs: 200,
        active_mass_millionths: 500_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    t.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 400_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    assert_eq!(t.observation_count(), 1);
}

#[test]
fn enrichment_tracker_drops_duplicate_timestamp() {
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    t.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 500_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    t.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 400_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    assert_eq!(t.observation_count(), 1);
}

#[test]
fn enrichment_tracker_discovery_velocity() {
    let obs = make_observations(10, 1000, 100, 500_000, 10_000, 0);
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    for o in obs {
        t.record(o);
    }
    let vel = t.discovery_velocity(10);
    assert!(vel > 0);
}

#[test]
fn enrichment_tracker_retirement_velocity() {
    let obs = make_observations(10, 1000, 100, 500_000, 0, 10_000);
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    for o in obs {
        t.record(o);
    }
    let vel = t.retirement_velocity(10);
    assert!(vel > 0);
}

#[test]
fn enrichment_tracker_net_burndown_positive() {
    let obs = make_observations(10, 1000, 100, 500_000, 5_000, 15_000);
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    for o in obs {
        t.record(o);
    }
    let (vel, positive) = t.net_burndown_velocity(10);
    assert!(positive);
    assert!(vel > 0);
}

#[test]
fn enrichment_tracker_net_burndown_negative() {
    let obs = make_observations(10, 1000, 100, 500_000, 15_000, 5_000);
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    for o in obs {
        t.record(o);
    }
    let (_vel, positive) = t.net_burndown_velocity(10);
    assert!(!positive);
}

#[test]
fn enrichment_tracker_dark_matter_fraction() {
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    t.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 300_000,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    assert_eq!(t.latest_dark_matter_fraction(), 300_000);
}

#[test]
fn enrichment_tracker_dark_matter_fraction_zero_surface() {
    let t = BurndownTracker::new(0, SecurityEpoch::from_raw(1));
    assert_eq!(t.latest_dark_matter_fraction(), MILLION);
}

#[test]
fn enrichment_tracker_content_hash_deterministic() {
    let obs = make_observations(5, 1000, 100, 500_000, 10_000, 5_000);
    let build = || {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        for o in &obs {
            t.record(o.clone());
        }
        t
    };
    assert_eq!(build().content_hash(), build().content_hash());
}

#[test]
fn enrichment_tracker_has_enough_boundary() {
    let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
    assert!(!t.has_enough_observations(1));
    t.record(BurndownObservation {
        timestamp_epoch_secs: 100,
        active_mass_millionths: 0,
        cumulative_discovered_millionths: 0,
        cumulative_retired_millionths: 0,
    });
    assert!(t.has_enough_observations(1));
    assert!(!t.has_enough_observations(2));
}

#[test]
fn enrichment_observation_content_hash_deterministic() {
    let o1 = BurndownObservation {
        timestamp_epoch_secs: 1000,
        active_mass_millionths: 200_000,
        cumulative_discovered_millionths: 100_000,
        cumulative_retired_millionths: 50_000,
    };
    let o2 = o1.clone();
    assert_eq!(o1.content_hash(), o2.content_hash());
}

#[test]
fn enrichment_observation_content_hash_varies() {
    let o1 = BurndownObservation {
        timestamp_epoch_secs: 1000,
        active_mass_millionths: 200_000,
        cumulative_discovered_millionths: 100_000,
        cumulative_retired_millionths: 50_000,
    };
    let o2 = BurndownObservation {
        timestamp_epoch_secs: 2000,
        ..o1.clone()
    };
    assert_ne!(o1.content_hash(), o2.content_hash());
}

// ===========================================================================
// Board state
// ===========================================================================

#[test]
fn enrichment_board_state_variant_count() {
    assert_eq!(BoardState::ALL.len(), 3);
}

#[test]
fn enrichment_board_state_permits_frontier_claim() {
    assert!(BoardState::Saturated.permits_frontier_claim());
    assert!(!BoardState::ScopeLimited.permits_frontier_claim());
    assert!(!BoardState::Stale.permits_frontier_claim());
}

// ===========================================================================
// Config validation
// ===========================================================================

#[test]
fn enrichment_config_threshold_over_million() {
    let c = SaturationConfig {
        saturation_threshold_millionths: MILLION + 1,
        ..SaturationConfig::default()
    };
    let violations = c.validate();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].field, "saturation_threshold_millionths");
}

#[test]
fn enrichment_config_ratchet_ceiling_over_million() {
    let c = SaturationConfig {
        ratchet_widening_ceiling_millionths: MILLION + 1,
        ..SaturationConfig::default()
    };
    let violations = c.validate();
    assert_eq!(violations.len(), 1);
}

#[test]
fn enrichment_config_zero_min_observations() {
    let c = SaturationConfig {
        min_observations: 0,
        ..SaturationConfig::default()
    };
    let violations = c.validate();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].field, "min_observations");
}

#[test]
fn enrichment_config_zero_velocity_window() {
    let c = SaturationConfig {
        velocity_window: 0,
        ..SaturationConfig::default()
    };
    let violations = c.validate();
    assert_eq!(violations.len(), 1);
}

#[test]
fn enrichment_config_zero_staleness() {
    let c = SaturationConfig {
        max_staleness_hours: 0,
        ..SaturationConfig::default()
    };
    let violations = c.validate();
    assert_eq!(violations.len(), 1);
}

#[test]
fn enrichment_config_multiple_violations() {
    let c = SaturationConfig {
        saturation_threshold_millionths: MILLION + 1,
        ratchet_widening_ceiling_millionths: MILLION + 1,
        min_observations: 0,
        velocity_window: 0,
        max_staleness_hours: 0,
        ..SaturationConfig::default()
    };
    let violations = c.validate();
    assert_eq!(violations.len(), 5);
}

// ===========================================================================
// Evaluator: saturation verdicts
// ===========================================================================

#[test]
fn enrichment_evaluator_saturated() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::Saturated);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| matches!(r, SaturationReason::LowDarkMatterWithPositiveBurndown))
    );
}

#[test]
fn enrichment_evaluator_scope_limited_high_dm() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 500_000, 5_000, 15_000);
    let eval = make_evaluator(500_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| matches!(r, SaturationReason::HighDarkMatterFraction { .. }))
    );
}

#[test]
fn enrichment_evaluator_scope_limited_negative_burndown() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 20_000, 5_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| matches!(r, SaturationReason::NegativeBurndown { .. }))
    );
}

#[test]
fn enrichment_evaluator_scope_limited_insufficient_observations() {
    let config = SaturationConfig {
        min_observations: 10,
        ..SaturationConfig::default()
    };
    let obs = make_observations(3, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| matches!(r, SaturationReason::InsufficientObservations { .. }))
    );
}

#[test]
fn enrichment_evaluator_scope_limited_invalid_config() {
    let config = SaturationConfig {
        min_observations: 0,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| matches!(r, SaturationReason::InvalidConfiguration { .. }))
    );
}

#[test]
fn enrichment_evaluator_scope_limited_velocity_below_minimum() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 999_999_999,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(2000);
    assert_eq!(verdict.state, BoardState::ScopeLimited);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| matches!(r, SaturationReason::InsufficientBurndownVelocity { .. }))
    );
}

#[test]
fn enrichment_evaluator_saturation_verdict_content_hash_deterministic() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let v1 = eval.evaluate_saturation(1500);
    let v2 = eval.evaluate_saturation(1500);
    assert_eq!(v1.content_hash(), v2.content_hash());
}

#[test]
fn enrichment_zero_active_mass_is_saturated() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 0,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 0, 0, 0);
    let eval = make_evaluator(0, MILLION, obs, config);
    let verdict = eval.evaluate_saturation(1500);
    assert_eq!(verdict.state, BoardState::Saturated);
    assert_eq!(verdict.dark_matter_fraction_millionths, 0);
}

// ===========================================================================
// Evaluator: freshness verdicts
// ===========================================================================

#[test]
fn enrichment_evaluator_fresh_board() {
    let config = SaturationConfig::default();
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_freshness(1500);
    assert!(verdict.is_fresh);
    assert!(matches!(verdict.reason, FreshnessReason::WithinWindow));
}

#[test]
fn enrichment_evaluator_stale_board() {
    let config = SaturationConfig {
        max_staleness_hours: 1,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_freshness(8600);
    assert!(!verdict.is_fresh);
    assert!(matches!(
        verdict.reason,
        FreshnessReason::ExceedsWindow { .. }
    ));
}

#[test]
fn enrichment_evaluator_no_observations_stale() {
    let config = SaturationConfig::default();
    let eval = make_evaluator(0, MILLION, vec![], config);
    let verdict = eval.evaluate_freshness(5000);
    assert!(!verdict.is_fresh);
    assert!(matches!(verdict.reason, FreshnessReason::NoObservations));
    assert_eq!(verdict.hours_since_last_observation, u64::MAX);
}

#[test]
fn enrichment_freshness_content_hash_deterministic() {
    let config = SaturationConfig::default();
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let v1 = eval.evaluate_freshness(1500);
    let v2 = eval.evaluate_freshness(1500);
    assert_eq!(v1.content_hash(), v2.content_hash());
}

// ===========================================================================
// Evaluator: ratchet widening verdicts
// ===========================================================================

#[test]
fn enrichment_ratchet_permitted_low_dm() {
    let config = SaturationConfig {
        min_observations: 3,
        ratchet_widening_ceiling_millionths: 200_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(verdict.permitted);
    assert!(matches!(
        verdict.reason,
        RatchetWideningReason::BelowCeiling
    ));
}

#[test]
fn enrichment_ratchet_blocked_high_dm() {
    let config = SaturationConfig {
        min_observations: 3,
        ratchet_widening_ceiling_millionths: 100_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 300_000, 5_000, 15_000);
    let eval = make_evaluator(300_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(!verdict.permitted);
    assert!(matches!(
        verdict.reason,
        RatchetWideningReason::AboveCeiling { .. }
    ));
}

#[test]
fn enrichment_ratchet_blocked_stale() {
    let config = SaturationConfig {
        min_observations: 3,
        max_staleness_hours: 1,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1_000_000);
    assert!(!verdict.permitted);
    assert!(matches!(verdict.reason, RatchetWideningReason::BoardStale));
}

#[test]
fn enrichment_ratchet_blocked_insufficient_data() {
    let config = SaturationConfig {
        min_observations: 10,
        ..SaturationConfig::default()
    };
    let obs = make_observations(3, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let verdict = eval.evaluate_ratchet_widening(1500);
    assert!(!verdict.permitted);
    assert!(matches!(
        verdict.reason,
        RatchetWideningReason::InsufficientData
    ));
}

#[test]
fn enrichment_ratchet_content_hash_deterministic() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let v1 = eval.evaluate_ratchet_widening(1500);
    let v2 = eval.evaluate_ratchet_widening(1500);
    assert_eq!(v1.content_hash(), v2.content_hash());
}

// ===========================================================================
// Full pipeline (evaluate)
// ===========================================================================

#[test]
fn enrichment_full_pipeline_saturated() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    assert_eq!(receipt.composite_state, BoardState::Saturated);
    assert_eq!(receipt.schema_version, DARK_MATTER_GATE_SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn enrichment_full_pipeline_scope_limited() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 500_000, 5_000, 15_000);
    let eval = make_evaluator(500_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    assert_eq!(receipt.composite_state, BoardState::ScopeLimited);
}

#[test]
fn enrichment_full_pipeline_stale_overrides_saturated() {
    let config = SaturationConfig {
        min_observations: 3,
        max_staleness_hours: 1,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1_000_000);
    assert_eq!(receipt.composite_state, BoardState::Stale);
}

#[test]
fn enrichment_full_pipeline_receipt_hash_deterministic() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let r1 = eval.evaluate(1500);
    let r2 = eval.evaluate(1500);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_full_pipeline_receipt_hash_varies_on_time() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let r1 = eval.evaluate(1500);
    let r2 = eval.evaluate(1501);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ===========================================================================
// Evidence emission
// ===========================================================================

#[test]
fn enrichment_evidence_emitted_correctly() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    assert_eq!(evidence.schema_version, DARK_MATTER_GATE_SCHEMA_VERSION);
    assert_eq!(evidence.bead_id, DARK_MATTER_GATE_BEAD_ID);
    assert_eq!(evidence.component, COMPONENT);
    assert_eq!(evidence.board_state, BoardState::Saturated);
}

#[test]
fn enrichment_evidence_estimate_summary() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    assert_eq!(evidence.estimate_summary.total_surface_millionths, MILLION);
    assert_eq!(evidence.estimate_summary.active_mass_millionths, 100_000);
    assert_eq!(evidence.estimate_summary.active_region_count, 1);
    assert_eq!(evidence.estimate_summary.retired_region_count, 0);
}

#[test]
fn enrichment_evidence_burndown_metrics() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    assert_eq!(evidence.burndown_metrics.observation_count, 5);
    assert!(evidence.burndown_metrics.time_span_secs > 0);
}

#[test]
fn enrichment_evidence_content_hash_deterministic() {
    let config = SaturationConfig {
        min_observations: 3,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let e1 = eval.emit_evidence(1500);
    let e2 = eval.emit_evidence(1500);
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_evidence_stale_board_state() {
    let config = SaturationConfig {
        min_observations: 3,
        max_staleness_hours: 1,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1_000_000);
    assert_eq!(evidence.board_state, BoardState::Stale);
}

// ===========================================================================
// Multi-region evaluator
// ===========================================================================

#[test]
fn enrichment_evaluator_multiple_regions() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut estimate = DarkMatterEstimate::new(MILLION, epoch, 1000);
    estimate.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        50_000,
        false,
    ));
    estimate.add_region(make_region(
        "r2",
        DarkMatterRegionKind::UnverifiedInterleaving,
        30_000,
        false,
    ));
    estimate.add_region(make_region(
        "r3",
        DarkMatterRegionKind::UntestedErrorRecovery,
        20_000,
        true,
    ));
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 80_000, 5_000, 15_000);
    let mut tracker = BurndownTracker::new(MILLION, epoch);
    for o in obs {
        tracker.record(o);
    }
    let eval = SaturationGateEvaluator::new(config, estimate, tracker);
    let receipt = eval.evaluate(1500);
    assert_eq!(receipt.composite_state, BoardState::Saturated);
}

#[test]
fn enrichment_evidence_with_multiple_kinds() {
    let epoch = SecurityEpoch::from_raw(1);
    let mut estimate = DarkMatterEstimate::new(MILLION, epoch, 1000);
    estimate.add_region(make_region(
        "r1",
        DarkMatterRegionKind::UntestedCodePath,
        50_000,
        false,
    ));
    estimate.add_region(make_region(
        "r2",
        DarkMatterRegionKind::UnverifiedInterleaving,
        30_000,
        false,
    ));
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 80_000, 5_000, 15_000);
    let mut tracker = BurndownTracker::new(MILLION, epoch);
    for o in obs {
        tracker.record(o);
    }
    let eval = SaturationGateEvaluator::new(config, estimate, tracker);
    let evidence = eval.emit_evidence(1500);
    assert!(!evidence.estimate_summary.mass_by_kind.is_empty());
    assert!(
        evidence
            .estimate_summary
            .mass_by_kind
            .contains_key("untested_code_path")
    );
    assert!(
        evidence
            .estimate_summary
            .mass_by_kind
            .contains_key("unverified_interleaving")
    );
}

// ===========================================================================
// JSON field-name stability
// ===========================================================================

#[test]
fn enrichment_region_json_fields() {
    let r = make_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"region_id\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"mass_millionths\""));
    assert!(json.contains("\"retired\""));
    assert!(json.contains("\"discovered_at_epoch_secs\""));
    assert!(json.contains("\"priority_weight_millionths\""));
}

#[test]
fn enrichment_observation_json_fields() {
    let obs = BurndownObservation {
        timestamp_epoch_secs: 1000,
        active_mass_millionths: 200_000,
        cumulative_discovered_millionths: 100_000,
        cumulative_retired_millionths: 50_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    assert!(json.contains("\"timestamp_epoch_secs\""));
    assert!(json.contains("\"active_mass_millionths\""));
    assert!(json.contains("\"cumulative_discovered_millionths\""));
    assert!(json.contains("\"cumulative_retired_millionths\""));
}

#[test]
fn enrichment_config_json_fields() {
    let c = SaturationConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"saturation_threshold_millionths\""));
    assert!(json.contains("\"min_observations\""));
    assert!(json.contains("\"velocity_window\""));
    assert!(json.contains("\"max_staleness_hours\""));
    assert!(json.contains("\"ratchet_widening_ceiling_millionths\""));
    assert!(json.contains("\"min_burndown_velocity_millionths\""));
}

#[test]
fn enrichment_freshness_verdict_json_fields() {
    let v = FreshnessVerdict {
        is_fresh: true,
        hours_since_last_observation: 0,
        max_staleness_hours: 168,
        reason: FreshnessReason::WithinWindow,
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 1000,
    };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"is_fresh\""));
    assert!(json.contains("\"hours_since_last_observation\""));
    assert!(json.contains("\"max_staleness_hours\""));
    assert!(json.contains("\"reason\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"verdict_at_epoch_secs\""));
}

#[test]
fn enrichment_ratchet_verdict_json_fields() {
    let v = RatchetWideningVerdict {
        permitted: true,
        dark_matter_fraction_millionths: 100_000,
        ceiling_millionths: 200_000,
        reason: RatchetWideningReason::BelowCeiling,
        epoch: SecurityEpoch::from_raw(1),
        verdict_at_epoch_secs: 1000,
    };
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"permitted\""));
    assert!(json.contains("\"dark_matter_fraction_millionths\""));
    assert!(json.contains("\"ceiling_millionths\""));
    assert!(json.contains("\"reason\""));
}

#[test]
fn enrichment_evidence_json_fields() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let evidence = eval.emit_evidence(1500);
    let json = serde_json::to_string(&evidence).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"bead_id\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"estimate_summary\""));
    assert!(json.contains("\"burndown_metrics\""));
    assert!(json.contains("\"board_state\""));
    assert!(json.contains("\"receipt_hash\""));
}

#[test]
fn enrichment_receipt_json_fields() {
    let config = SaturationConfig {
        min_observations: 3,
        min_burndown_velocity_millionths: 10_000,
        ..SaturationConfig::default()
    };
    let obs = make_observations(5, 1000, 100, 100_000, 5_000, 15_000);
    let eval = make_evaluator(100_000, MILLION, obs, config);
    let receipt = eval.evaluate(1500);
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"receipt_hash\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"saturation_verdict\""));
    assert!(json.contains("\"freshness_verdict\""));
    assert!(json.contains("\"ratchet_widening_verdict\""));
    assert!(json.contains("\"composite_state\""));
    assert!(json.contains("\"issued_at_epoch_secs\""));
}
