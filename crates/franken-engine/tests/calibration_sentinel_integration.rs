#![forbid(unsafe_code)]

//! Integration tests for the `calibration_sentinel` module.
//!
//! Exercises the public API from outside the crate: sentinel creation and
//! update, state classification, observability cell construction, promotion
//! rule evaluation (FailClosed, RequireCalibration, RequireObservability,
//! SuppressClaim, AllowWithWarning), report building, manifest generation,
//! content-hash determinism, serde round-trips, Display formatting, and
//! edge cases (zero thresholds, large values, empty cells, mixed states).

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

use frankenengine_engine::calibration_sentinel::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sentinel(id: &str, kind: SentinelKind, threshold: u64, value: u64) -> CalibrationSentinel {
    let mut s = create_sentinel(id, kind, threshold);
    update_sentinel(&mut s, value);
    s
}

fn green_cell(id: &str, domain: &str, rule: PromotionRule) -> ObservabilityCell {
    let s1 = sentinel("g-err", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("g-cov", SentinelKind::Coverage, 800_000, 1_000_000);
    build_cell(id, domain, vec![s1, s2], rule)
}

fn yellow_cell(id: &str, domain: &str, rule: PromotionRule) -> ObservabilityCell {
    let s1 = sentinel("y-err", SentinelKind::ErrorBound, 1_000_000, 850_000);
    let s2 = sentinel("y-cov", SentinelKind::Coverage, 800_000, 1_000_000);
    build_cell(id, domain, vec![s1, s2], rule)
}

fn red_cell(id: &str, domain: &str, rule: PromotionRule) -> ObservabilityCell {
    let s1 = sentinel("r-err", SentinelKind::ErrorBound, 100_000, 200_000);
    let s2 = sentinel("r-cov", SentinelKind::Coverage, 800_000, 1_000_000);
    build_cell(id, domain, vec![s1, s2], rule)
}

// ---------------------------------------------------------------------------
// SentinelKind / SentinelState / PromotionRule enums
// ---------------------------------------------------------------------------

#[test]
fn test_sentinel_kind_enumeration_and_bounds() {
    let all = SentinelKind::all();
    assert_eq!(all.len(), 5);
    // Upper-bound kinds: ErrorBound, Freshness, Drift
    assert!(SentinelKind::ErrorBound.is_upper_bound());
    assert!(SentinelKind::Freshness.is_upper_bound());
    assert!(SentinelKind::Drift.is_upper_bound());
    // Lower-bound kinds: Coverage, Completeness
    assert!(!SentinelKind::Coverage.is_upper_bound());
    assert!(!SentinelKind::Completeness.is_upper_bound());
    // as_str matches Display for every kind
    for kind in all {
        assert_eq!(kind.as_str(), format!("{kind}"));
    }
}

#[test]
fn test_sentinel_state_healthy_and_degraded() {
    assert!(SentinelState::Green.is_healthy());
    assert!(!SentinelState::Yellow.is_healthy());
    assert!(!SentinelState::Red.is_healthy());
    assert!(!SentinelState::Unknown.is_healthy());
    assert!(!SentinelState::Green.is_degraded());
    assert!(SentinelState::Yellow.is_degraded());
    assert!(SentinelState::Red.is_degraded());
    assert!(!SentinelState::Unknown.is_degraded());
    for s in &[
        SentinelState::Green,
        SentinelState::Yellow,
        SentinelState::Red,
        SentinelState::Unknown,
    ] {
        assert_eq!(s.as_str(), format!("{s}"));
    }
}

#[test]
fn test_promotion_rule_as_str_and_display() {
    let pairs = [
        (PromotionRule::FailClosed, "fail_closed"),
        (PromotionRule::RequireCalibration, "require_calibration"),
        (PromotionRule::RequireObservability, "require_observability"),
        (PromotionRule::SuppressClaim, "suppress_claim"),
        (PromotionRule::AllowWithWarning, "allow_with_warning"),
    ];
    for (rule, expected) in &pairs {
        assert_eq!(rule.as_str(), *expected);
        assert_eq!(format!("{rule}"), *expected);
    }
}

// ---------------------------------------------------------------------------
// SentinelError
// ---------------------------------------------------------------------------

#[test]
fn test_sentinel_error_display_and_serde() {
    let errors = vec![
        SentinelError::ThresholdViolation,
        SentinelError::MissingSentinel,
        SentinelError::CalibrationStale,
        SentinelError::InternalError("boom".into()),
    ];
    assert!(format!("{}", errors[0]).contains("threshold"));
    assert!(format!("{}", errors[1]).contains("missing"));
    assert!(format!("{}", errors[2]).contains("stale"));
    assert!(format!("{}", errors[3]).contains("boom"));
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SentinelError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// create_sentinel / update_sentinel
// ---------------------------------------------------------------------------

#[test]
fn test_create_sentinel_initial_state_and_hash() {
    let s = create_sentinel("s1", SentinelKind::ErrorBound, 500_000);
    assert_eq!(s.state, SentinelState::Unknown);
    assert_eq!(s.current_value_millionths, 0);
    assert_eq!(s.threshold_millionths, 500_000);
    assert_eq!(s.sentinel_id, "s1");
    assert_eq!(s.kind, SentinelKind::ErrorBound);
    assert_ne!(s.content_hash, ContentHash::compute(&[]));
}

#[test]
fn test_update_sentinel_upper_bound_all_states() {
    // Green: value well below threshold
    let mut s = create_sentinel("ub", SentinelKind::ErrorBound, 500_000);
    assert_eq!(update_sentinel(&mut s, 100_000), SentinelState::Green);
    assert_eq!(s.current_value_millionths, 100_000);
    // Yellow: value above 80% but at or below threshold
    assert_eq!(update_sentinel(&mut s, 450_000), SentinelState::Yellow);
    // Red: value above threshold
    assert_eq!(update_sentinel(&mut s, 600_000), SentinelState::Red);
}

#[test]
fn test_update_sentinel_lower_bound_all_states() {
    // Coverage: threshold=800k, green_boundary=960k
    let mut s = create_sentinel("lb", SentinelKind::Coverage, 800_000);
    // Green: value >= green_boundary
    assert_eq!(update_sentinel(&mut s, 1_000_000), SentinelState::Green);
    // Yellow: threshold <= value < green_boundary
    assert_eq!(update_sentinel(&mut s, 850_000), SentinelState::Yellow);
    // Red: value < threshold
    assert_eq!(update_sentinel(&mut s, 500_000), SentinelState::Red);
}

#[test]
fn test_update_sentinel_refreshes_content_hash() {
    let mut s = create_sentinel("hr", SentinelKind::ErrorBound, 500_000);
    let hash_before = s.content_hash;
    update_sentinel(&mut s, 200_000);
    assert_ne!(s.content_hash, hash_before);
}

// ---------------------------------------------------------------------------
// classify_state edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_classify_state_zero_threshold() {
    assert_eq!(classify_state(0, 0), SentinelState::Green);
    assert_eq!(classify_state(1, 0), SentinelState::Red);
}

#[test]
fn test_classify_state_boundary_values() {
    // Exact threshold => Yellow
    assert_eq!(classify_state(500_000, 500_000), SentinelState::Yellow);
    // At yellow boundary (80% of 500k = 400k) => Green
    assert_eq!(classify_state(400_000, 500_000), SentinelState::Green);
    // Just above yellow boundary => Yellow
    assert_eq!(classify_state(400_001, 500_000), SentinelState::Yellow);
}

#[test]
fn test_classify_state_large_threshold_no_overflow() {
    let threshold = u64::MAX / 2;
    let state = classify_state(0, threshold);
    assert_eq!(state, SentinelState::Green);
}

// ---------------------------------------------------------------------------
// ObservabilityCell
// ---------------------------------------------------------------------------

#[test]
fn test_build_cell_aggregates_state() {
    let gc = green_cell("gc", "latency", PromotionRule::FailClosed);
    assert_eq!(gc.overall_state, SentinelState::Green);
    assert_eq!(gc.cell_id, "gc");
    assert_eq!(gc.supremacy_domain, "latency");

    let yc = yellow_cell("yc", "memory", PromotionRule::FailClosed);
    assert_eq!(yc.overall_state, SentinelState::Yellow);

    let rc = red_cell("rc", "throughput", PromotionRule::FailClosed);
    assert_eq!(rc.overall_state, SentinelState::Red);
}

#[test]
fn test_build_cell_empty_sentinels_is_unknown() {
    let cell = build_cell("empty", "latency", vec![], PromotionRule::FailClosed);
    assert_eq!(cell.overall_state, SentinelState::Unknown);
}

#[test]
fn test_cell_count_in_state() {
    let cell = green_cell("cs", "memory", PromotionRule::FailClosed);
    assert_eq!(cell.count_in_state(SentinelState::Green), 2);
    assert_eq!(cell.count_in_state(SentinelState::Red), 0);
}

#[test]
fn test_cell_hash_deterministic_and_domain_sensitive() {
    let c1 = green_cell("det", "latency", PromotionRule::FailClosed);
    let c2 = green_cell("det", "latency", PromotionRule::FailClosed);
    assert_eq!(c1.compute_hash(), c2.compute_hash());

    let s1 = sentinel("hd", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("hd", SentinelKind::ErrorBound, 500_000, 100_000);
    let ca = build_cell("same", "domain_a", vec![s1], PromotionRule::FailClosed);
    let cb = build_cell("same", "domain_b", vec![s2], PromotionRule::FailClosed);
    assert_ne!(ca.compute_hash(), cb.compute_hash());
}

#[test]
fn test_cell_display_format() {
    let cell = green_cell("disp", "latency", PromotionRule::FailClosed);
    let display = format!("{cell}");
    assert!(display.contains("disp"));
    assert!(display.contains("latency"));
    assert!(display.contains("green"));
    assert!(display.contains("sentinels=2"));
}

// ---------------------------------------------------------------------------
// evaluate_promotion — FailClosed
// ---------------------------------------------------------------------------

#[test]
fn test_fail_closed_green_allows() {
    let d = evaluate_promotion(&green_cell("fc-g", "lat", PromotionRule::FailClosed));
    assert!(d.allowed);
    assert!(d.suppression_reasons.is_empty());
    assert_eq!(d.rule, PromotionRule::FailClosed);
    assert_eq!(d.cell_id, "fc-g");
}

#[test]
fn test_fail_closed_yellow_and_red_block() {
    let dy = evaluate_promotion(&yellow_cell("fc-y", "lat", PromotionRule::FailClosed));
    assert!(!dy.allowed);
    assert!(!dy.suppression_reasons.is_empty());

    let dr = evaluate_promotion(&red_cell("fc-r", "lat", PromotionRule::FailClosed));
    assert!(!dr.allowed);
    assert!(!dr.suppression_reasons.is_empty());
}

#[test]
fn test_fail_closed_empty_cell_blocks() {
    let cell = build_cell("empty-fc", "test", vec![], PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    assert!(!d.allowed);
}

// ---------------------------------------------------------------------------
// evaluate_promotion — RequireCalibration
// ---------------------------------------------------------------------------

#[test]
fn test_require_calibration_green_and_yellow_allow() {
    let dg = evaluate_promotion(&green_cell(
        "rc-g",
        "lat",
        PromotionRule::RequireCalibration,
    ));
    assert!(dg.allowed);
    assert!(dg.suppression_reasons.is_empty());

    let dy = evaluate_promotion(&yellow_cell(
        "rc-y",
        "lat",
        PromotionRule::RequireCalibration,
    ));
    assert!(dy.allowed);
    assert!(!dy.suppression_reasons.is_empty());
}

#[test]
fn test_require_calibration_red_and_unknown_block() {
    let dr = evaluate_promotion(&red_cell("rc-r", "lat", PromotionRule::RequireCalibration));
    assert!(!dr.allowed);

    let s = create_sentinel("unk-rc", SentinelKind::Coverage, 800_000);
    let cell = build_cell(
        "unk-rc-c",
        "test",
        vec![s],
        PromotionRule::RequireCalibration,
    );
    let du = evaluate_promotion(&cell);
    assert!(!du.allowed);
}

// ---------------------------------------------------------------------------
// evaluate_promotion — RequireObservability
// ---------------------------------------------------------------------------

#[test]
fn test_require_observability_green_and_yellow_allow() {
    let dg = evaluate_promotion(&green_cell(
        "ro-g",
        "lat",
        PromotionRule::RequireObservability,
    ));
    assert!(dg.allowed);

    let dy = evaluate_promotion(&yellow_cell(
        "ro-y",
        "lat",
        PromotionRule::RequireObservability,
    ));
    assert!(dy.allowed);
    assert!(!dy.suppression_reasons.is_empty());
}

#[test]
fn test_require_observability_red_and_unknown_block() {
    let dr = evaluate_promotion(&red_cell(
        "ro-r",
        "lat",
        PromotionRule::RequireObservability,
    ));
    assert!(!dr.allowed);

    let s = create_sentinel("unk-ro", SentinelKind::ErrorBound, 500_000);
    let cell = build_cell(
        "unk-ro-c",
        "test",
        vec![s],
        PromotionRule::RequireObservability,
    );
    let du = evaluate_promotion(&cell);
    assert!(!du.allowed);
}

// ---------------------------------------------------------------------------
// evaluate_promotion — SuppressClaim
// ---------------------------------------------------------------------------

#[test]
fn test_suppress_claim_always_blocks() {
    let dg = evaluate_promotion(&green_cell("sc-g", "lat", PromotionRule::SuppressClaim));
    assert!(!dg.allowed);
    assert!(dg.suppression_reasons[0].contains("SuppressClaim"));

    let dr = evaluate_promotion(&red_cell("sc-r", "lat", PromotionRule::SuppressClaim));
    assert!(!dr.allowed);
}

// ---------------------------------------------------------------------------
// evaluate_promotion — AllowWithWarning
// ---------------------------------------------------------------------------

#[test]
fn test_allow_with_warning_always_allows() {
    let dg = evaluate_promotion(&green_cell("aw-g", "lat", PromotionRule::AllowWithWarning));
    assert!(dg.allowed);
    assert!(dg.suppression_reasons.is_empty());

    let dr = evaluate_promotion(&red_cell("aw-r", "lat", PromotionRule::AllowWithWarning));
    assert!(dr.allowed);
    assert!(!dr.suppression_reasons.is_empty());

    let s = create_sentinel("aw-unk", SentinelKind::Freshness, 1_000_000);
    let cell = build_cell("aw-unk-c", "test", vec![s], PromotionRule::AllowWithWarning);
    let du = evaluate_promotion(&cell);
    assert!(du.allowed);
}

// ---------------------------------------------------------------------------
// PromotionDecision details
// ---------------------------------------------------------------------------

#[test]
fn test_decision_determinism_and_display() {
    let cell = green_cell("det-d", "domain", PromotionRule::FailClosed);
    let d1 = evaluate_promotion(&cell);
    let d2 = evaluate_promotion(&cell);
    assert_eq!(d1.decision_id, d2.decision_id);
    assert_eq!(d1.content_hash, d2.content_hash);

    let allowed_str = format!("{d1}");
    assert!(allowed_str.contains("ALLOWED"));
    assert!(allowed_str.contains("det-d"));

    let blocked_cell = red_cell("bl-d", "lat", PromotionRule::FailClosed);
    let db = evaluate_promotion(&blocked_cell);
    assert!(format!("{db}").contains("BLOCKED"));
}

// ---------------------------------------------------------------------------
// build_report
// ---------------------------------------------------------------------------

#[test]
fn test_build_report_green_and_red_counts() {
    let c1 = green_cell("rpt1", "a", PromotionRule::FailClosed);
    let c2 = red_cell("rpt2", "b", PromotionRule::FailClosed);
    let c3 = green_cell("rpt3", "c", PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2, c3]);
    assert_eq!(report.green_count, 2);
    assert_eq!(report.red_count, 1);
    assert_eq!(report.cells.len(), 3);
    assert_eq!(report.decisions.len(), 3);
}

#[test]
fn test_build_report_epoch_preserved() {
    let epoch = SecurityEpoch::from_raw(42);
    let report = build_report(
        epoch,
        vec![green_cell("ep1", "lat", PromotionRule::FailClosed)],
    );
    assert_eq!(report.epoch, epoch);
}

#[test]
fn test_build_report_empty_cells() {
    let report = build_report(SecurityEpoch::from_raw(0), vec![]);
    assert_eq!(report.green_count, 0);
    assert_eq!(report.red_count, 0);
    assert!(report.cells.is_empty());
    assert!(report.decisions.is_empty());
    assert_eq!(report.green_fraction_millionths(), 0);
    assert_eq!(report.allowed_fraction_millionths(), 0);
}

#[test]
fn test_build_report_fractions() {
    let c1 = green_cell("gf1", "a", PromotionRule::FailClosed);
    let c2 = red_cell("gf2", "b", PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2]);
    assert_eq!(report.green_fraction_millionths(), 500_000);
    // 1 allowed (green) out of 2 decisions
    assert_eq!(report.allowed_fraction_millionths(), 500_000);
}

#[test]
fn test_build_report_hash_deterministic() {
    let r1 = build_report(
        SecurityEpoch::from_raw(5),
        vec![green_cell("hd1", "lat", PromotionRule::FailClosed)],
    );
    let r2 = build_report(
        SecurityEpoch::from_raw(5),
        vec![green_cell("hd1", "lat", PromotionRule::FailClosed)],
    );
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.report_id, r2.report_id);
}

#[test]
fn test_build_report_display_format() {
    let report = build_report(
        SecurityEpoch::from_raw(7),
        vec![green_cell("rd1", "lat", PromotionRule::FailClosed)],
    );
    let s = format!("{report}");
    assert!(s.contains("epoch:7"));
    assert!(s.contains("green=1"));
    assert!(s.contains("red=0"));
}

#[test]
fn test_report_mixed_rules_all_allowed() {
    let c1 = green_cell("mx1", "a", PromotionRule::FailClosed);
    let c2 = yellow_cell("mx2", "b", PromotionRule::RequireCalibration);
    let c3 = red_cell("mx3", "c", PromotionRule::AllowWithWarning);
    let report = build_report(SecurityEpoch::from_raw(10), vec![c1, c2, c3]);
    assert_eq!(report.decisions.iter().filter(|d| d.allowed).count(), 3);
}

#[test]
fn test_report_yellow_not_counted_as_green_or_red() {
    let report = build_report(
        SecurityEpoch::from_raw(1),
        vec![yellow_cell("yc1", "a", PromotionRule::RequireCalibration)],
    );
    assert_eq!(report.green_count, 0);
    assert_eq!(report.red_count, 0);
}

// ---------------------------------------------------------------------------
// Sentinel manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_structure_and_determinism() {
    let r1 = franken_engine_sentinel_manifest();
    assert_eq!(r1.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(r1.cells.len(), 5);
    assert_eq!(r1.decisions.len(), 5);

    let r2 = franken_engine_sentinel_manifest();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.report_id, r2.report_id);
}

#[test]
fn test_manifest_covers_all_promotion_rules() {
    let report = franken_engine_sentinel_manifest();
    let rules: Vec<PromotionRule> = report.decisions.iter().map(|d| d.rule).collect();
    assert!(rules.contains(&PromotionRule::FailClosed));
    assert!(rules.contains(&PromotionRule::RequireCalibration));
    assert!(rules.contains(&PromotionRule::RequireObservability));
    assert!(rules.contains(&PromotionRule::SuppressClaim));
    assert!(rules.contains(&PromotionRule::AllowWithWarning));
}

#[test]
fn test_manifest_promotion_outcomes() {
    let report = franken_engine_sentinel_manifest();
    let find = |r: PromotionRule| report.decisions.iter().find(|d| d.rule == r).unwrap();

    // FailClosed with all-green cell => allowed
    assert!(find(PromotionRule::FailClosed).allowed);
    // SuppressClaim always blocks
    assert!(!find(PromotionRule::SuppressClaim).allowed);
    // AllowWithWarning allows even with red, with reasons
    let aw = find(PromotionRule::AllowWithWarning);
    assert!(aw.allowed);
    assert!(!aw.suppression_reasons.is_empty());
    // Report has at least some green and red cells
    assert!(report.green_count >= 1);
    assert!(report.red_count >= 1);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_serde_roundtrip_enums() {
    for kind in SentinelKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        let back: SentinelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
    for state in &[
        SentinelState::Green,
        SentinelState::Yellow,
        SentinelState::Red,
        SentinelState::Unknown,
    ] {
        let json = serde_json::to_string(state).unwrap();
        let back: SentinelState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
    for rule in &[
        PromotionRule::FailClosed,
        PromotionRule::RequireCalibration,
        PromotionRule::RequireObservability,
        PromotionRule::SuppressClaim,
        PromotionRule::AllowWithWarning,
    ] {
        let json = serde_json::to_string(rule).unwrap();
        let back: PromotionRule = serde_json::from_str(&json).unwrap();
        assert_eq!(*rule, back);
    }
}

#[test]
fn test_serde_roundtrip_sentinel() {
    let s = sentinel("serde-s", SentinelKind::Drift, 300_000, 50_000);
    let json = serde_json::to_string(&s).unwrap();
    let back: CalibrationSentinel = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn test_serde_roundtrip_cell() {
    let cell = green_cell("serde-c", "latency", PromotionRule::FailClosed);
    let json = serde_json::to_string(&cell).unwrap();
    let back: ObservabilityCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

#[test]
fn test_serde_roundtrip_decision() {
    let d = evaluate_promotion(&red_cell("serde-d", "thr", PromotionRule::FailClosed));
    let json = serde_json::to_string(&d).unwrap();
    let back: PromotionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn test_serde_roundtrip_report() {
    let c1 = green_cell("sr1", "a", PromotionRule::FailClosed);
    let c2 = red_cell("sr2", "b", PromotionRule::RequireCalibration);
    let report = build_report(SecurityEpoch::from_raw(3), vec![c1, c2]);
    let json = serde_json::to_string(&report).unwrap();
    let back: SentinelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn test_serde_roundtrip_manifest() {
    let report = franken_engine_sentinel_manifest();
    let json = serde_json::to_string(&report).unwrap();
    let back: SentinelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Content hash tamper evidence
// ---------------------------------------------------------------------------

#[test]
fn test_sentinel_hash_sensitivity() {
    let s1 = sentinel("hv", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("hv", SentinelKind::ErrorBound, 500_000, 200_000);
    assert_ne!(s1.content_hash, s2.content_hash);

    let s3 = sentinel("hv", SentinelKind::Drift, 500_000, 100_000);
    assert_ne!(s1.content_hash, s3.content_hash);

    let s4 = sentinel("other-id", SentinelKind::ErrorBound, 500_000, 100_000);
    assert_ne!(s1.content_hash, s4.content_hash);
}

#[test]
fn test_report_hash_changes_with_epoch() {
    let r1 = build_report(
        SecurityEpoch::from_raw(1),
        vec![green_cell("eh", "lat", PromotionRule::FailClosed)],
    );
    let r2 = build_report(
        SecurityEpoch::from_raw(2),
        vec![green_cell("eh", "lat", PromotionRule::FailClosed)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_max_threshold_zero_value() {
    let mut s = create_sentinel("max-t", SentinelKind::ErrorBound, u64::MAX);
    let state = update_sentinel(&mut s, 0);
    assert_eq!(state, SentinelState::Green);
}

#[test]
fn test_constants_accessible() {
    assert!(CALIBRATION_SENTINEL_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CALIBRATION_SENTINEL_SCHEMA_VERSION.ends_with(".v1"));
    assert_eq!(CALIBRATION_SENTINEL_BEAD_ID, "bd-1lsy.11.20.3");
}

#[test]
fn test_sentinel_display_contains_key_fields() {
    let s = sentinel("ds1", SentinelKind::Drift, 300_000, 50_000);
    let display = format!("{s}");
    assert!(display.contains("ds1"));
    assert!(display.contains("drift"));
    assert!(display.contains("50000"));
    assert!(display.contains("300000"));
    assert!(display.contains("green"));
}

// ===========================================================================
// Enrichment tests (PearlTower, 2026-03-12)
// ===========================================================================

// ---------------------------------------------------------------------------
// SentinelKind — Clone, Debug, serde JSON field names, Ord
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sentinel_kind_clone_equals_original() {
    for kind in SentinelKind::all() {
        let cloned = kind.clone();
        assert_eq!(*kind, cloned);
    }
}

#[test]
fn enrichment_sentinel_kind_debug_contains_variant_name() {
    assert!(format!("{:?}", SentinelKind::ErrorBound).contains("ErrorBound"));
    assert!(format!("{:?}", SentinelKind::Coverage).contains("Coverage"));
    assert!(format!("{:?}", SentinelKind::Freshness).contains("Freshness"));
    assert!(format!("{:?}", SentinelKind::Drift).contains("Drift"));
    assert!(format!("{:?}", SentinelKind::Completeness).contains("Completeness"));
}

#[test]
fn enrichment_sentinel_kind_serde_json_uses_snake_case() {
    let json = serde_json::to_string(&SentinelKind::ErrorBound).unwrap();
    assert_eq!(json, "\"error_bound\"");
    let json2 = serde_json::to_string(&SentinelKind::Coverage).unwrap();
    assert_eq!(json2, "\"coverage\"");
    let json3 = serde_json::to_string(&SentinelKind::Freshness).unwrap();
    assert_eq!(json3, "\"freshness\"");
    let json4 = serde_json::to_string(&SentinelKind::Drift).unwrap();
    assert_eq!(json4, "\"drift\"");
    let json5 = serde_json::to_string(&SentinelKind::Completeness).unwrap();
    assert_eq!(json5, "\"completeness\"");
}

#[test]
fn enrichment_sentinel_kind_all_has_stable_order() {
    let a = SentinelKind::all();
    let b = SentinelKind::all();
    assert_eq!(a, b);
    assert_eq!(a[0], SentinelKind::ErrorBound);
    assert_eq!(a[1], SentinelKind::Coverage);
    assert_eq!(a[2], SentinelKind::Freshness);
    assert_eq!(a[3], SentinelKind::Drift);
    assert_eq!(a[4], SentinelKind::Completeness);
}

#[test]
fn enrichment_sentinel_kind_upper_bound_lower_bound_partition() {
    let upper: Vec<&SentinelKind> = SentinelKind::all()
        .iter()
        .filter(|k| k.is_upper_bound())
        .collect();
    let lower: Vec<&SentinelKind> = SentinelKind::all()
        .iter()
        .filter(|k| !k.is_upper_bound())
        .collect();
    assert_eq!(upper.len(), 3);
    assert_eq!(lower.len(), 2);
    assert!(upper.contains(&&SentinelKind::ErrorBound));
    assert!(upper.contains(&&SentinelKind::Freshness));
    assert!(upper.contains(&&SentinelKind::Drift));
    assert!(lower.contains(&&SentinelKind::Coverage));
    assert!(lower.contains(&&SentinelKind::Completeness));
}

// ---------------------------------------------------------------------------
// SentinelState — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sentinel_state_clone_equals() {
    let states = [
        SentinelState::Green,
        SentinelState::Yellow,
        SentinelState::Red,
        SentinelState::Unknown,
    ];
    for s in &states {
        let c = s.clone();
        assert_eq!(*s, c);
    }
}

#[test]
fn enrichment_sentinel_state_debug_format() {
    assert!(format!("{:?}", SentinelState::Green).contains("Green"));
    assert!(format!("{:?}", SentinelState::Yellow).contains("Yellow"));
    assert!(format!("{:?}", SentinelState::Red).contains("Red"));
    assert!(format!("{:?}", SentinelState::Unknown).contains("Unknown"));
}

#[test]
fn enrichment_sentinel_state_serde_json_uses_snake_case() {
    assert_eq!(
        serde_json::to_string(&SentinelState::Green).unwrap(),
        "\"green\""
    );
    assert_eq!(
        serde_json::to_string(&SentinelState::Yellow).unwrap(),
        "\"yellow\""
    );
    assert_eq!(
        serde_json::to_string(&SentinelState::Red).unwrap(),
        "\"red\""
    );
    assert_eq!(
        serde_json::to_string(&SentinelState::Unknown).unwrap(),
        "\"unknown\""
    );
}

#[test]
fn enrichment_sentinel_state_unknown_is_neither_healthy_nor_degraded() {
    let u = SentinelState::Unknown;
    assert!(!u.is_healthy());
    assert!(!u.is_degraded());
}

// ---------------------------------------------------------------------------
// PromotionRule — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_promotion_rule_clone_equals() {
    let rules = [
        PromotionRule::FailClosed,
        PromotionRule::RequireCalibration,
        PromotionRule::RequireObservability,
        PromotionRule::SuppressClaim,
        PromotionRule::AllowWithWarning,
    ];
    for r in &rules {
        let c = r.clone();
        assert_eq!(*r, c);
    }
}

#[test]
fn enrichment_promotion_rule_debug_format() {
    assert!(format!("{:?}", PromotionRule::FailClosed).contains("FailClosed"));
    assert!(format!("{:?}", PromotionRule::RequireCalibration).contains("RequireCalibration"));
    assert!(format!("{:?}", PromotionRule::RequireObservability).contains("RequireObservability"));
    assert!(format!("{:?}", PromotionRule::SuppressClaim).contains("SuppressClaim"));
    assert!(format!("{:?}", PromotionRule::AllowWithWarning).contains("AllowWithWarning"));
}

#[test]
fn enrichment_promotion_rule_serde_json_snake_case() {
    assert_eq!(
        serde_json::to_string(&PromotionRule::FailClosed).unwrap(),
        "\"fail_closed\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionRule::RequireCalibration).unwrap(),
        "\"require_calibration\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionRule::RequireObservability).unwrap(),
        "\"require_observability\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionRule::SuppressClaim).unwrap(),
        "\"suppress_claim\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionRule::AllowWithWarning).unwrap(),
        "\"allow_with_warning\""
    );
}

// ---------------------------------------------------------------------------
// SentinelError — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sentinel_error_clone_equals() {
    let errs = vec![
        SentinelError::ThresholdViolation,
        SentinelError::MissingSentinel,
        SentinelError::CalibrationStale,
        SentinelError::InternalError("msg".into()),
    ];
    for e in &errs {
        let c = e.clone();
        assert_eq!(*e, c);
    }
}

#[test]
fn enrichment_sentinel_error_debug_contains_variant() {
    assert!(format!("{:?}", SentinelError::ThresholdViolation).contains("ThresholdViolation"));
    assert!(format!("{:?}", SentinelError::MissingSentinel).contains("MissingSentinel"));
    assert!(format!("{:?}", SentinelError::CalibrationStale).contains("CalibrationStale"));
    assert!(format!("{:?}", SentinelError::InternalError("x".into())).contains("InternalError"));
}

#[test]
fn enrichment_sentinel_error_internal_error_empty_string() {
    let e = SentinelError::InternalError(String::new());
    let display = format!("{e}");
    assert!(display.contains("internal error:"));
}

#[test]
fn enrichment_sentinel_error_serde_json_roundtrip_all_variants() {
    let variants: Vec<SentinelError> = vec![
        SentinelError::ThresholdViolation,
        SentinelError::MissingSentinel,
        SentinelError::CalibrationStale,
        SentinelError::InternalError("special chars: <>\"'&".into()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SentinelError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// classify_state — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_state_value_zero_nonzero_threshold() {
    let state = classify_state(0, 1_000_000);
    assert_eq!(state, SentinelState::Green);
}

#[test]
fn enrichment_classify_state_one_below_threshold() {
    // value = threshold - 1, should be Yellow (since 499_999 > 400_000)
    let state = classify_state(499_999, 500_000);
    assert_eq!(state, SentinelState::Yellow);
}

#[test]
fn enrichment_classify_state_one_above_threshold() {
    let state = classify_state(500_001, 500_000);
    assert_eq!(state, SentinelState::Red);
}

#[test]
fn enrichment_classify_state_small_threshold_yellow_boundary() {
    // Threshold=10, yellow_boundary=8 (80% of 10 = 8)
    assert_eq!(classify_state(8, 10), SentinelState::Green);
    assert_eq!(classify_state(9, 10), SentinelState::Yellow);
    assert_eq!(classify_state(10, 10), SentinelState::Yellow);
    assert_eq!(classify_state(11, 10), SentinelState::Red);
}

#[test]
fn enrichment_classify_state_threshold_one() {
    // Threshold=1, yellow_boundary=0 (80% of 1 = 0)
    assert_eq!(classify_state(0, 1), SentinelState::Green);
    assert_eq!(classify_state(1, 1), SentinelState::Yellow);
    assert_eq!(classify_state(2, 1), SentinelState::Red);
}

#[test]
fn enrichment_classify_state_very_large_values_no_panic() {
    let state = classify_state(u64::MAX, u64::MAX);
    // value == threshold => Yellow
    assert_eq!(state, SentinelState::Yellow);
}

#[test]
fn enrichment_classify_state_max_value_max_threshold() {
    // value = MAX, threshold = MAX => Yellow (equals threshold, above yellow_boundary)
    let state = classify_state(u64::MAX, u64::MAX);
    assert_eq!(state, SentinelState::Yellow);
}

// ---------------------------------------------------------------------------
// CalibrationSentinel — struct fields, Display, Debug, compute_hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sentinel_struct_fields_preserved_after_create() {
    let s = create_sentinel("test-id-123", SentinelKind::Completeness, 750_000);
    assert_eq!(s.sentinel_id, "test-id-123");
    assert_eq!(s.kind, SentinelKind::Completeness);
    assert_eq!(s.threshold_millionths, 750_000);
    assert_eq!(s.current_value_millionths, 0);
    assert_eq!(s.state, SentinelState::Unknown);
}

#[test]
fn enrichment_sentinel_compute_hash_matches_stored_hash() {
    let s = sentinel("chk", SentinelKind::Freshness, 200_000, 50_000);
    assert_eq!(s.content_hash, s.compute_hash());
}

#[test]
fn enrichment_sentinel_compute_hash_deterministic() {
    let s1 = sentinel("det", SentinelKind::Drift, 300_000, 100_000);
    let s2 = sentinel("det", SentinelKind::Drift, 300_000, 100_000);
    assert_eq!(s1.compute_hash(), s2.compute_hash());
}

#[test]
fn enrichment_sentinel_hash_sensitive_to_id() {
    let s1 = sentinel("id-a", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("id-b", SentinelKind::ErrorBound, 500_000, 100_000);
    assert_ne!(s1.content_hash, s2.content_hash);
}

#[test]
fn enrichment_sentinel_hash_sensitive_to_threshold() {
    let s1 = sentinel("thr", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("thr", SentinelKind::ErrorBound, 600_000, 100_000);
    assert_ne!(s1.content_hash, s2.content_hash);
}

#[test]
fn enrichment_sentinel_debug_format() {
    let s = sentinel("dbg-s", SentinelKind::Coverage, 800_000, 1_000_000);
    let dbg = format!("{s:?}");
    assert!(dbg.contains("CalibrationSentinel"));
    assert!(dbg.contains("dbg-s"));
    assert!(dbg.contains("Coverage"));
}

#[test]
fn enrichment_sentinel_display_format_upper_bound_red() {
    let s = sentinel("red-s", SentinelKind::ErrorBound, 100_000, 200_000);
    let display = format!("{s}");
    assert!(display.contains("red-s"));
    assert!(display.contains("error_bound"));
    assert!(display.contains("200000"));
    assert!(display.contains("100000"));
    assert!(display.contains("red"));
}

#[test]
fn enrichment_sentinel_display_format_lower_bound_yellow() {
    // Coverage: threshold=800k, value=850k => yellow
    let s = sentinel("yel-s", SentinelKind::Coverage, 800_000, 850_000);
    let display = format!("{s}");
    assert!(display.contains("yel-s"));
    assert!(display.contains("coverage"));
    assert!(display.contains("yellow"));
}

#[test]
fn enrichment_sentinel_clone_equality() {
    let s = sentinel("cl-s", SentinelKind::Drift, 300_000, 50_000);
    let cloned = s.clone();
    assert_eq!(s, cloned);
    assert_eq!(s.content_hash, cloned.content_hash);
}

// ---------------------------------------------------------------------------
// update_sentinel — lower-bound kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_update_sentinel_completeness_green() {
    // Completeness: lower-bound. threshold=900k, green_boundary=900k + 180k = 1_080_000
    // value=1_100_000 >= 1_080_000 => Green
    let mut s = create_sentinel("comp-g", SentinelKind::Completeness, 900_000);
    let state = update_sentinel(&mut s, 1_100_000);
    assert_eq!(state, SentinelState::Green);
}

#[test]
fn enrichment_update_sentinel_completeness_yellow() {
    // Completeness: threshold=900k, green_boundary=1_080_000
    // value=950_000 => Yellow (>= 900k, < 1_080_000)
    let mut s = create_sentinel("comp-y", SentinelKind::Completeness, 900_000);
    let state = update_sentinel(&mut s, 950_000);
    assert_eq!(state, SentinelState::Yellow);
}

#[test]
fn enrichment_update_sentinel_completeness_red() {
    // Completeness: threshold=900k, value=800k < 900k => Red
    let mut s = create_sentinel("comp-r", SentinelKind::Completeness, 900_000);
    let state = update_sentinel(&mut s, 800_000);
    assert_eq!(state, SentinelState::Red);
}

#[test]
fn enrichment_update_sentinel_freshness_all_states() {
    let mut s = create_sentinel("fresh", SentinelKind::Freshness, 1_000_000);
    // Green: value <= 800k
    assert_eq!(update_sentinel(&mut s, 500_000), SentinelState::Green);
    // Yellow: value in (800k, 1M]
    assert_eq!(update_sentinel(&mut s, 900_000), SentinelState::Yellow);
    // Red: value > 1M
    assert_eq!(update_sentinel(&mut s, 1_500_000), SentinelState::Red);
}

#[test]
fn enrichment_update_sentinel_multiple_updates_track_latest() {
    let mut s = create_sentinel("multi", SentinelKind::ErrorBound, 500_000);
    update_sentinel(&mut s, 100_000);
    assert_eq!(s.current_value_millionths, 100_000);
    assert_eq!(s.state, SentinelState::Green);
    update_sentinel(&mut s, 600_000);
    assert_eq!(s.current_value_millionths, 600_000);
    assert_eq!(s.state, SentinelState::Red);
    update_sentinel(&mut s, 0);
    assert_eq!(s.current_value_millionths, 0);
    assert_eq!(s.state, SentinelState::Green);
}

#[test]
fn enrichment_update_sentinel_hash_changes_on_each_update() {
    let mut s = create_sentinel("hseq", SentinelKind::Drift, 300_000);
    let h0 = s.content_hash;
    update_sentinel(&mut s, 100_000);
    let h1 = s.content_hash;
    update_sentinel(&mut s, 200_000);
    let h2 = s.content_hash;
    assert_ne!(h0, h1);
    assert_ne!(h1, h2);
    assert_ne!(h0, h2);
}

// ---------------------------------------------------------------------------
// ObservabilityCell — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cell_compute_overall_state_matches_stored() {
    let cell = green_cell("cos", "domain", PromotionRule::FailClosed);
    assert_eq!(cell.compute_overall_state(), cell.overall_state);
}

#[test]
fn enrichment_cell_with_single_sentinel() {
    let s = sentinel("solo", SentinelKind::ErrorBound, 500_000, 100_000);
    let cell = build_cell("solo-cell", "latency", vec![s], PromotionRule::FailClosed);
    assert_eq!(cell.sentinels.len(), 1);
    assert_eq!(cell.overall_state, SentinelState::Green);
    assert_eq!(cell.count_in_state(SentinelState::Green), 1);
}

#[test]
fn enrichment_cell_mixed_green_and_unknown() {
    let s1 = sentinel("g", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = create_sentinel("unk", SentinelKind::Coverage, 800_000); // Unknown
    let cell = build_cell("mix-unk", "lat", vec![s1, s2], PromotionRule::FailClosed);
    assert_eq!(cell.overall_state, SentinelState::Unknown);
}

#[test]
fn enrichment_cell_mixed_yellow_and_unknown() {
    let s1 = sentinel("y", SentinelKind::ErrorBound, 1_000_000, 850_000); // Yellow
    let s2 = create_sentinel("unk", SentinelKind::Coverage, 800_000); // Unknown
    let cell = build_cell("y-unk", "lat", vec![s1, s2], PromotionRule::FailClosed);
    // Unknown has higher priority than Yellow
    assert_eq!(cell.overall_state, SentinelState::Unknown);
}

#[test]
fn enrichment_cell_red_overrides_everything() {
    let s1 = sentinel("g", SentinelKind::ErrorBound, 500_000, 100_000); // Green
    let s2 = sentinel("y", SentinelKind::ErrorBound, 1_000_000, 850_000); // Yellow
    let s3 = create_sentinel("unk", SentinelKind::Coverage, 800_000); // Unknown
    let s4 = sentinel("r", SentinelKind::ErrorBound, 100_000, 200_000); // Red
    let cell = build_cell(
        "all-mix",
        "lat",
        vec![s1, s2, s3, s4],
        PromotionRule::FailClosed,
    );
    assert_eq!(cell.overall_state, SentinelState::Red);
}

#[test]
fn enrichment_cell_count_in_state_for_various_states() {
    let s1 = sentinel("g1", SentinelKind::ErrorBound, 500_000, 100_000); // Green
    let s2 = sentinel("g2", SentinelKind::Drift, 300_000, 50_000); // Green
    let s3 = sentinel("y1", SentinelKind::ErrorBound, 1_000_000, 850_000); // Yellow
    let s4 = sentinel("r1", SentinelKind::ErrorBound, 100_000, 200_000); // Red
    let cell = build_cell(
        "counts",
        "lat",
        vec![s1, s2, s3, s4],
        PromotionRule::FailClosed,
    );
    assert_eq!(cell.count_in_state(SentinelState::Green), 2);
    assert_eq!(cell.count_in_state(SentinelState::Yellow), 1);
    assert_eq!(cell.count_in_state(SentinelState::Red), 1);
    assert_eq!(cell.count_in_state(SentinelState::Unknown), 0);
}

#[test]
fn enrichment_cell_debug_format() {
    let cell = green_cell("dbg-cell", "mem", PromotionRule::RequireCalibration);
    let dbg = format!("{cell:?}");
    assert!(dbg.contains("ObservabilityCell"));
    assert!(dbg.contains("dbg-cell"));
}

#[test]
fn enrichment_cell_display_shows_rule() {
    let cell = green_cell("rule-cell", "lat", PromotionRule::AllowWithWarning);
    let display = format!("{cell}");
    assert!(display.contains("allow_with_warning"));
}

#[test]
fn enrichment_cell_hash_sensitive_to_rule() {
    let s1 = sentinel("h", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("h", SentinelKind::ErrorBound, 500_000, 100_000);
    let c1 = build_cell("same", "lat", vec![s1], PromotionRule::FailClosed);
    let c2 = build_cell("same", "lat", vec![s2], PromotionRule::AllowWithWarning);
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn enrichment_cell_hash_sensitive_to_cell_id() {
    let s1 = sentinel("h", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("h", SentinelKind::ErrorBound, 500_000, 100_000);
    let c1 = build_cell("cell-a", "lat", vec![s1], PromotionRule::FailClosed);
    let c2 = build_cell("cell-b", "lat", vec![s2], PromotionRule::FailClosed);
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn enrichment_cell_clone_equality() {
    let cell = green_cell("cl-cell", "throughput", PromotionRule::RequireObservability);
    let cloned = cell.clone();
    assert_eq!(cell, cloned);
    assert_eq!(cell.compute_hash(), cloned.compute_hash());
}

// ---------------------------------------------------------------------------
// PromotionDecision — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_fields_populated_correctly() {
    let cell = green_cell("dec-fields", "lat", PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    assert_eq!(d.cell_id, "dec-fields");
    assert_eq!(d.rule, PromotionRule::FailClosed);
    assert!(d.allowed);
    assert!(d.suppression_reasons.is_empty());
    assert!(!d.decision_id.is_empty());
    assert_ne!(d.content_hash, ContentHash::compute(&[]));
}

#[test]
fn enrichment_decision_compute_hash_matches_stored() {
    let cell = red_cell("dec-hash", "lat", PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    assert_eq!(d.content_hash, d.compute_hash());
}

#[test]
fn enrichment_decision_debug_format() {
    let cell = green_cell("dec-dbg", "lat", PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    let dbg = format!("{d:?}");
    assert!(dbg.contains("PromotionDecision"));
    assert!(dbg.contains("dec-dbg"));
}

#[test]
fn enrichment_decision_display_blocked_contains_reasons_count() {
    let cell = red_cell("dec-blk", "lat", PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    let display = format!("{d}");
    assert!(display.contains("BLOCKED"));
    assert!(display.contains("reasons="));
}

#[test]
fn enrichment_decision_display_allowed_shows_rule() {
    let cell = green_cell("dec-allow", "lat", PromotionRule::RequireCalibration);
    let d = evaluate_promotion(&cell);
    let display = format!("{d}");
    assert!(display.contains("ALLOWED"));
    assert!(display.contains("require_calibration"));
}

#[test]
fn enrichment_decision_clone_equality() {
    let cell = red_cell("dec-cl", "lat", PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    let cloned = d.clone();
    assert_eq!(d, cloned);
}

#[test]
fn enrichment_decision_id_is_deterministic() {
    let cell = green_cell("det-id", "lat", PromotionRule::FailClosed);
    let d1 = evaluate_promotion(&cell);
    let d2 = evaluate_promotion(&cell);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn enrichment_decision_id_differs_for_different_rules() {
    let s1 = sentinel("x", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("x", SentinelKind::ErrorBound, 500_000, 100_000);
    let c1 = build_cell("same-id", "lat", vec![s1], PromotionRule::FailClosed);
    let c2 = build_cell("same-id", "lat", vec![s2], PromotionRule::AllowWithWarning);
    let d1 = evaluate_promotion(&c1);
    let d2 = evaluate_promotion(&c2);
    assert_ne!(d1.decision_id, d2.decision_id);
}

// ---------------------------------------------------------------------------
// evaluate_promotion — suppression reason content
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fail_closed_yellow_suppression_reason_mentions_sentinel() {
    let s1 = sentinel("y-fb", SentinelKind::ErrorBound, 1_000_000, 850_000);
    let cell = build_cell("fc-sup", "lat", vec![s1], PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    assert!(!d.allowed);
    assert!(!d.suppression_reasons.is_empty());
    assert!(d.suppression_reasons[0].contains("y-fb"));
    assert!(d.suppression_reasons[0].contains("yellow"));
}

#[test]
fn enrichment_fail_closed_red_suppression_reason_mentions_sentinel() {
    let s1 = sentinel("r-fb", SentinelKind::ErrorBound, 100_000, 200_000);
    let cell = build_cell("fc-red-sup", "lat", vec![s1], PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    assert!(!d.allowed);
    assert!(d.suppression_reasons[0].contains("r-fb"));
    assert!(d.suppression_reasons[0].contains("red"));
}

#[test]
fn enrichment_require_calibration_yellow_warning_mentions_sentinel_id() {
    let s1 = sentinel("rc-y-warn", SentinelKind::ErrorBound, 1_000_000, 850_000);
    let cell = build_cell(
        "rc-warn",
        "lat",
        vec![s1],
        PromotionRule::RequireCalibration,
    );
    let d = evaluate_promotion(&cell);
    assert!(d.allowed);
    assert!(!d.suppression_reasons.is_empty());
    assert!(d.suppression_reasons[0].contains("rc-y-warn"));
}

#[test]
fn enrichment_suppress_claim_reason_mentions_cell_id() {
    let cell = green_cell("sc-reason", "lat", PromotionRule::SuppressClaim);
    let d = evaluate_promotion(&cell);
    assert!(!d.allowed);
    assert!(d.suppression_reasons[0].contains("sc-reason"));
    assert!(d.suppression_reasons[0].contains("SuppressClaim"));
}

#[test]
fn enrichment_allow_with_warning_red_records_reasons() {
    let s1 = sentinel("aw-r-s", SentinelKind::ErrorBound, 100_000, 200_000);
    let cell = build_cell(
        "aw-red-cell",
        "lat",
        vec![s1],
        PromotionRule::AllowWithWarning,
    );
    let d = evaluate_promotion(&cell);
    assert!(d.allowed);
    assert!(!d.suppression_reasons.is_empty());
    assert!(d.suppression_reasons[0].contains("aw-r-s"));
}

#[test]
fn enrichment_allow_with_warning_unknown_records_reasons() {
    let s1 = create_sentinel("aw-unk-s", SentinelKind::ErrorBound, 500_000);
    let cell = build_cell(
        "aw-unk-cell",
        "lat",
        vec![s1],
        PromotionRule::AllowWithWarning,
    );
    let d = evaluate_promotion(&cell);
    assert!(d.allowed);
    // Unknown sentinel should produce suppression reasons
    assert!(!d.suppression_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// SentinelReport — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_debug_format() {
    let report = build_report(
        SecurityEpoch::from_raw(7),
        vec![green_cell("rpt-dbg", "lat", PromotionRule::FailClosed)],
    );
    let dbg = format!("{report:?}");
    assert!(dbg.contains("SentinelReport"));
    assert!(dbg.contains("rpt-dbg"));
}

#[test]
fn enrichment_report_display_shows_cells_count() {
    let c1 = green_cell("rd1", "a", PromotionRule::FailClosed);
    let c2 = green_cell("rd2", "b", PromotionRule::FailClosed);
    let c3 = red_cell("rd3", "c", PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(3), vec![c1, c2, c3]);
    let display = format!("{report}");
    assert!(display.contains("cells=3"));
    assert!(display.contains("decisions=3"));
}

#[test]
fn enrichment_report_clone_equality() {
    let report = build_report(
        SecurityEpoch::from_raw(5),
        vec![green_cell("cl-rpt", "lat", PromotionRule::FailClosed)],
    );
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

#[test]
fn enrichment_report_compute_hash_matches_stored() {
    let report = build_report(
        SecurityEpoch::from_raw(5),
        vec![green_cell("hash-rpt", "lat", PromotionRule::FailClosed)],
    );
    assert_eq!(report.content_hash, report.compute_hash());
}

#[test]
fn enrichment_report_green_fraction_all_green() {
    let c1 = green_cell("ag1", "a", PromotionRule::FailClosed);
    let c2 = green_cell("ag2", "b", PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2]);
    assert_eq!(report.green_fraction_millionths(), 1_000_000);
}

#[test]
fn enrichment_report_green_fraction_all_red() {
    let c1 = red_cell("ar1", "a", PromotionRule::FailClosed);
    let c2 = red_cell("ar2", "b", PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2]);
    assert_eq!(report.green_fraction_millionths(), 0);
}

#[test]
fn enrichment_report_allowed_fraction_all_blocked() {
    let c1 = red_cell("ab1", "a", PromotionRule::FailClosed);
    let c2 = red_cell("ab2", "b", PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2]);
    assert_eq!(report.allowed_fraction_millionths(), 0);
}

#[test]
fn enrichment_report_allowed_fraction_all_allowed() {
    let c1 = green_cell("aa1", "a", PromotionRule::FailClosed);
    let c2 = green_cell("aa2", "b", PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2]);
    assert_eq!(report.allowed_fraction_millionths(), 1_000_000);
}

#[test]
fn enrichment_report_allowed_fraction_mixed_rules() {
    // FailClosed+green => allowed
    let c1 = green_cell("af1", "a", PromotionRule::FailClosed);
    // SuppressClaim => blocked regardless
    let c2 = green_cell("af2", "b", PromotionRule::SuppressClaim);
    // RequireCalibration+yellow => allowed
    let c3 = yellow_cell("af3", "c", PromotionRule::RequireCalibration);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2, c3]);
    // 2 allowed, 1 blocked out of 3 => 666_666
    assert_eq!(report.allowed_fraction_millionths(), 666_666);
}

#[test]
fn enrichment_report_hash_changes_with_different_cells() {
    let r1 = build_report(
        SecurityEpoch::from_raw(1),
        vec![green_cell("h-a", "lat", PromotionRule::FailClosed)],
    );
    let r2 = build_report(
        SecurityEpoch::from_raw(1),
        vec![red_cell("h-b", "lat", PromotionRule::FailClosed)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_report_id_starts_with_rpt_prefix() {
    let report = build_report(
        SecurityEpoch::from_raw(1),
        vec![green_cell("id-rpt", "lat", PromotionRule::FailClosed)],
    );
    assert!(report.report_id.starts_with("rpt-"));
}

#[test]
fn enrichment_report_yellow_cells_not_counted_green_nor_red() {
    let c1 = yellow_cell("yc-cnt-1", "a", PromotionRule::RequireCalibration);
    let c2 = yellow_cell("yc-cnt-2", "b", PromotionRule::RequireCalibration);
    let report = build_report(SecurityEpoch::from_raw(1), vec![c1, c2]);
    assert_eq!(report.green_count, 0);
    assert_eq!(report.red_count, 0);
    assert_eq!(report.cells.len(), 2);
}

#[test]
fn enrichment_report_unknown_cells_not_counted_green_nor_red() {
    let s = create_sentinel("unk-cnt", SentinelKind::Coverage, 800_000);
    let cell = build_cell("unk-cnt-cell", "lat", vec![s], PromotionRule::FailClosed);
    let report = build_report(SecurityEpoch::from_raw(1), vec![cell]);
    assert_eq!(report.green_count, 0);
    assert_eq!(report.red_count, 0);
}

// ---------------------------------------------------------------------------
// Manifest — additional contract tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_has_five_distinct_cells() {
    let report = franken_engine_sentinel_manifest();
    let cell_ids: Vec<&str> = report.cells.iter().map(|c| c.cell_id.as_str()).collect();
    // All unique
    let mut sorted = cell_ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), cell_ids.len());
}

#[test]
fn enrichment_manifest_has_five_distinct_decisions() {
    let report = franken_engine_sentinel_manifest();
    let dec_ids: Vec<&str> = report
        .decisions
        .iter()
        .map(|d| d.decision_id.as_str())
        .collect();
    let mut sorted = dec_ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), dec_ids.len());
}

#[test]
fn enrichment_manifest_decision_cell_ids_match_cells() {
    let report = franken_engine_sentinel_manifest();
    let cell_ids: Vec<&str> = report.cells.iter().map(|c| c.cell_id.as_str()).collect();
    for d in &report.decisions {
        assert!(cell_ids.contains(&d.cell_id.as_str()));
    }
}

#[test]
fn enrichment_manifest_require_calibration_allows_yellow() {
    let report = franken_engine_sentinel_manifest();
    let rc_decision = report
        .decisions
        .iter()
        .find(|d| d.rule == PromotionRule::RequireCalibration)
        .unwrap();
    assert!(rc_decision.allowed);
}

#[test]
fn enrichment_manifest_require_observability_allows_green() {
    let report = franken_engine_sentinel_manifest();
    let ro_decision = report
        .decisions
        .iter()
        .find(|d| d.rule == PromotionRule::RequireObservability)
        .unwrap();
    assert!(ro_decision.allowed);
}

#[test]
fn enrichment_manifest_serde_json_field_names() {
    let report = franken_engine_sentinel_manifest();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"report_id\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"cells\""));
    assert!(json.contains("\"decisions\""));
    assert!(json.contains("\"green_count\""));
    assert!(json.contains("\"red_count\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_manifest_cell_serde_json_field_names() {
    let report = franken_engine_sentinel_manifest();
    let cell_json = serde_json::to_string(&report.cells[0]).unwrap();
    assert!(cell_json.contains("\"cell_id\""));
    assert!(cell_json.contains("\"supremacy_domain\""));
    assert!(cell_json.contains("\"sentinels\""));
    assert!(cell_json.contains("\"promotion_rule\""));
    assert!(cell_json.contains("\"overall_state\""));
}

#[test]
fn enrichment_manifest_sentinel_serde_json_field_names() {
    let report = franken_engine_sentinel_manifest();
    let sentinel_json = serde_json::to_string(&report.cells[0].sentinels[0]).unwrap();
    assert!(sentinel_json.contains("\"sentinel_id\""));
    assert!(sentinel_json.contains("\"kind\""));
    assert!(sentinel_json.contains("\"threshold_millionths\""));
    assert!(sentinel_json.contains("\"current_value_millionths\""));
    assert!(sentinel_json.contains("\"state\""));
    assert!(sentinel_json.contains("\"content_hash\""));
}

#[test]
fn enrichment_manifest_decision_serde_json_field_names() {
    let report = franken_engine_sentinel_manifest();
    let dec_json = serde_json::to_string(&report.decisions[0]).unwrap();
    assert!(dec_json.contains("\"decision_id\""));
    assert!(dec_json.contains("\"cell_id\""));
    assert!(dec_json.contains("\"rule\""));
    assert!(dec_json.contains("\"allowed\""));
    assert!(dec_json.contains("\"suppression_reasons\""));
    assert!(dec_json.contains("\"content_hash\""));
}

// ---------------------------------------------------------------------------
// Serde — deserialization from invalid data
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_invalid_sentinel_kind_rejected() {
    let result = serde_json::from_str::<SentinelKind>("\"nonexistent_kind\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_invalid_sentinel_state_rejected() {
    let result = serde_json::from_str::<SentinelState>("\"blue\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_invalid_promotion_rule_rejected() {
    let result = serde_json::from_str::<PromotionRule>("\"allow_everything\"");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Decision ID determinism across cell variations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_id_differs_for_different_cell_ids() {
    let s1 = sentinel("x", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("x", SentinelKind::ErrorBound, 500_000, 100_000);
    let c1 = build_cell("cell-alpha", "lat", vec![s1], PromotionRule::FailClosed);
    let c2 = build_cell("cell-beta", "lat", vec![s2], PromotionRule::FailClosed);
    let d1 = evaluate_promotion(&c1);
    let d2 = evaluate_promotion(&c2);
    assert_ne!(d1.decision_id, d2.decision_id);
}

#[test]
fn enrichment_decision_id_starts_with_dec_prefix() {
    let cell = green_cell("dec-pfx", "lat", PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    assert!(d.decision_id.starts_with("dec-"));
}

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_contains_module_name() {
    assert!(CALIBRATION_SENTINEL_SCHEMA_VERSION.contains("calibration-sentinel"));
}

#[test]
fn enrichment_bead_id_format() {
    assert!(CALIBRATION_SENTINEL_BEAD_ID.starts_with("bd-"));
    assert!(CALIBRATION_SENTINEL_BEAD_ID.contains('.'));
}

// ---------------------------------------------------------------------------
// Cross-type serde: full report with all state combinations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_report_serde_roundtrip_all_states() {
    let sg = sentinel("all-g", SentinelKind::ErrorBound, 500_000, 100_000);
    let sy = sentinel("all-y", SentinelKind::ErrorBound, 1_000_000, 850_000);
    let sr = sentinel("all-r", SentinelKind::ErrorBound, 100_000, 200_000);
    let su = create_sentinel("all-u", SentinelKind::Coverage, 800_000);

    let c1 = build_cell("c-all-g", "a", vec![sg], PromotionRule::FailClosed);
    let c2 = build_cell("c-all-y", "b", vec![sy], PromotionRule::RequireCalibration);
    let c3 = build_cell("c-all-r", "c", vec![sr], PromotionRule::AllowWithWarning);
    let c4 = build_cell("c-all-u", "d", vec![su], PromotionRule::SuppressClaim);

    let report = build_report(SecurityEpoch::from_raw(99), vec![c1, c2, c3, c4]);
    let json = serde_json::to_string_pretty(&report).unwrap();
    let back: SentinelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
    assert_eq!(report.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// Empty/edge string identifiers
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sentinel_empty_id_is_valid() {
    let s = create_sentinel("", SentinelKind::ErrorBound, 500_000);
    assert_eq!(s.sentinel_id, "");
    let mut s2 = s.clone();
    update_sentinel(&mut s2, 100_000);
    assert_eq!(s2.state, SentinelState::Green);
}

#[test]
fn enrichment_cell_empty_domain_is_valid() {
    let s = sentinel("e-dom", SentinelKind::ErrorBound, 500_000, 100_000);
    let cell = build_cell("e-cell", "", vec![s], PromotionRule::FailClosed);
    assert_eq!(cell.supremacy_domain, "");
    let d = evaluate_promotion(&cell);
    assert!(d.allowed);
}

#[test]
fn enrichment_sentinel_long_id_preserves_full_string() {
    let long_id = "a".repeat(1000);
    let s = create_sentinel(&long_id, SentinelKind::Drift, 300_000);
    assert_eq!(s.sentinel_id, long_id);
}

// ---------------------------------------------------------------------------
// ObservabilityCell — build with all five sentinel kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cell_with_all_five_kinds() {
    let s1 = sentinel("eb", SentinelKind::ErrorBound, 500_000, 100_000);
    let s2 = sentinel("cov", SentinelKind::Coverage, 800_000, 1_000_000);
    let s3 = sentinel("fr", SentinelKind::Freshness, 1_000_000, 200_000);
    let s4 = sentinel("dr", SentinelKind::Drift, 300_000, 50_000);
    let s5 = sentinel("comp", SentinelKind::Completeness, 700_000, 900_000);
    let cell = build_cell(
        "five-kinds",
        "full",
        vec![s1, s2, s3, s4, s5],
        PromotionRule::FailClosed,
    );
    assert_eq!(cell.sentinels.len(), 5);
    // All should be green
    assert_eq!(cell.overall_state, SentinelState::Green);
    assert_eq!(cell.count_in_state(SentinelState::Green), 5);
}

// ---------------------------------------------------------------------------
// Determinism — multiple evaluations produce identical results
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multiple_evaluations_identical_decisions() {
    let cell = yellow_cell("det-eval", "lat", PromotionRule::RequireCalibration);
    let results: Vec<PromotionDecision> = (0..10).map(|_| evaluate_promotion(&cell)).collect();
    for r in &results {
        assert_eq!(r.decision_id, results[0].decision_id);
        assert_eq!(r.content_hash, results[0].content_hash);
        assert_eq!(r.allowed, results[0].allowed);
        assert_eq!(
            r.suppression_reasons.len(),
            results[0].suppression_reasons.len()
        );
    }
}

#[test]
fn enrichment_multiple_report_builds_identical() {
    let make_cells = || {
        vec![
            green_cell("mr-1", "a", PromotionRule::FailClosed),
            red_cell("mr-2", "b", PromotionRule::AllowWithWarning),
        ]
    };
    let r1 = build_report(SecurityEpoch::from_raw(42), make_cells());
    let r2 = build_report(SecurityEpoch::from_raw(42), make_cells());
    assert_eq!(r1.report_id, r2.report_id);
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.green_count, r2.green_count);
    assert_eq!(r1.red_count, r2.red_count);
}
