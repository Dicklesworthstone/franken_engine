#![forbid(unsafe_code)]

//! Integration tests for the `calibration_sentinel` module.
//!
//! Exercises the public API from outside the crate: sentinel creation and
//! update, state classification, observability cell construction, promotion
//! rule evaluation (FailClosed, RequireCalibration, RequireObservability,
//! SuppressClaim, AllowWithWarning), report building, manifest generation,
//! content-hash determinism, serde round-trips, Display formatting, and
//! edge cases (zero thresholds, large values, empty cells, mixed states).

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
    for s in &[SentinelState::Green, SentinelState::Yellow, SentinelState::Red, SentinelState::Unknown] {
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
    let hash_before = s.content_hash.clone();
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
    let dg = evaluate_promotion(&green_cell("rc-g", "lat", PromotionRule::RequireCalibration));
    assert!(dg.allowed);
    assert!(dg.suppression_reasons.is_empty());

    let dy = evaluate_promotion(&yellow_cell("rc-y", "lat", PromotionRule::RequireCalibration));
    assert!(dy.allowed);
    assert!(!dy.suppression_reasons.is_empty());
}

#[test]
fn test_require_calibration_red_and_unknown_block() {
    let dr = evaluate_promotion(&red_cell("rc-r", "lat", PromotionRule::RequireCalibration));
    assert!(!dr.allowed);

    let s = create_sentinel("unk-rc", SentinelKind::Coverage, 800_000);
    let cell = build_cell("unk-rc-c", "test", vec![s], PromotionRule::RequireCalibration);
    let du = evaluate_promotion(&cell);
    assert!(!du.allowed);
}

// ---------------------------------------------------------------------------
// evaluate_promotion — RequireObservability
// ---------------------------------------------------------------------------

#[test]
fn test_require_observability_green_and_yellow_allow() {
    let dg = evaluate_promotion(&green_cell("ro-g", "lat", PromotionRule::RequireObservability));
    assert!(dg.allowed);

    let dy = evaluate_promotion(&yellow_cell("ro-y", "lat", PromotionRule::RequireObservability));
    assert!(dy.allowed);
    assert!(!dy.suppression_reasons.is_empty());
}

#[test]
fn test_require_observability_red_and_unknown_block() {
    let dr = evaluate_promotion(&red_cell("ro-r", "lat", PromotionRule::RequireObservability));
    assert!(!dr.allowed);

    let s = create_sentinel("unk-ro", SentinelKind::ErrorBound, 500_000);
    let cell = build_cell("unk-ro-c", "test", vec![s], PromotionRule::RequireObservability);
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
    let report = build_report(epoch, vec![green_cell("ep1", "lat", PromotionRule::FailClosed)]);
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
    for state in &[SentinelState::Green, SentinelState::Yellow, SentinelState::Red, SentinelState::Unknown] {
        let json = serde_json::to_string(state).unwrap();
        let back: SentinelState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
    for rule in &[
        PromotionRule::FailClosed, PromotionRule::RequireCalibration,
        PromotionRule::RequireObservability, PromotionRule::SuppressClaim,
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
    let r1 = build_report(SecurityEpoch::from_raw(1), vec![green_cell("eh", "lat", PromotionRule::FailClosed)]);
    let r2 = build_report(SecurityEpoch::from_raw(2), vec![green_cell("eh", "lat", PromotionRule::FailClosed)]);
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
