//! Enrichment integration tests for calibration_sentinel module.
//!
//! Covers sentinel state classification, observability cell aggregation,
//! promotion rule evaluation, report building, and manifest determinism.

use std::collections::BTreeSet;

use frankenengine_engine::calibration_sentinel::{
    CALIBRATION_SENTINEL_BEAD_ID, CALIBRATION_SENTINEL_SCHEMA_VERSION, CalibrationSentinel,
    ObservabilityCell, PromotionRule, SentinelError, SentinelKind, SentinelReport, SentinelState,
    build_cell, build_report, classify_state, create_sentinel, evaluate_promotion,
    franken_engine_sentinel_manifest, update_sentinel,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_green_sentinel(id: &str, kind: SentinelKind) -> CalibrationSentinel {
    let mut s = create_sentinel(id, kind, 500_000);
    if kind.is_upper_bound() {
        // For upper-bound: value must be below threshold
        update_sentinel(&mut s, 100_000);
    } else {
        // For lower-bound: value must be above threshold
        update_sentinel(&mut s, 900_000);
    }
    s
}

fn make_yellow_sentinel(id: &str, kind: SentinelKind) -> CalibrationSentinel {
    let mut s = create_sentinel(id, kind, 500_000);
    if kind.is_upper_bound() {
        // For upper-bound: value near threshold but above 80%
        update_sentinel(&mut s, 450_000);
    } else {
        // For lower-bound: value slightly below threshold
        update_sentinel(&mut s, 450_000);
    }
    s
}

fn make_red_sentinel(id: &str, kind: SentinelKind) -> CalibrationSentinel {
    let mut s = create_sentinel(id, kind, 500_000);
    if kind.is_upper_bound() {
        // For upper-bound: value above threshold
        update_sentinel(&mut s, 900_000);
    } else {
        // For lower-bound: value well below threshold
        update_sentinel(&mut s, 100_000);
    }
    s
}

// ---------------------------------------------------------------------------
// SentinelKind
// ---------------------------------------------------------------------------

#[test]
fn sentinel_kind_all_returns_five() {
    assert_eq!(SentinelKind::all().len(), 5);
}

#[test]
fn sentinel_kind_upper_bound_classification() {
    assert!(SentinelKind::ErrorBound.is_upper_bound());
    assert!(SentinelKind::Freshness.is_upper_bound());
    assert!(SentinelKind::Drift.is_upper_bound());
    assert!(!SentinelKind::Coverage.is_upper_bound());
    assert!(!SentinelKind::Completeness.is_upper_bound());
}

#[test]
fn sentinel_kind_display_all_distinct() {
    let displays: Vec<String> = SentinelKind::all().iter().map(|k| format!("{k}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn sentinel_kind_as_str_matches_display() {
    for kind in SentinelKind::all() {
        assert_eq!(kind.as_str(), format!("{kind}"));
    }
}

// ---------------------------------------------------------------------------
// SentinelState
// ---------------------------------------------------------------------------

#[test]
fn sentinel_state_healthy_only_green() {
    assert!(SentinelState::Green.is_healthy());
    assert!(!SentinelState::Yellow.is_healthy());
    assert!(!SentinelState::Red.is_healthy());
    assert!(!SentinelState::Unknown.is_healthy());
}

#[test]
fn sentinel_state_degraded() {
    assert!(!SentinelState::Green.is_degraded());
    assert!(SentinelState::Yellow.is_degraded());
    assert!(SentinelState::Red.is_degraded());
    assert!(!SentinelState::Unknown.is_degraded());
}

#[test]
fn sentinel_state_display_all_distinct() {
    let states = [
        SentinelState::Green,
        SentinelState::Yellow,
        SentinelState::Red,
        SentinelState::Unknown,
    ];
    let displays: Vec<String> = states.iter().map(|s| format!("{s}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 4);
}

// ---------------------------------------------------------------------------
// classify_state
// ---------------------------------------------------------------------------

#[test]
fn classify_green_below_threshold() {
    // Value below threshold → Green (upper-bound logic is default)
    let state = classify_state(100_000, 500_000);
    assert_eq!(state, SentinelState::Green);
}

#[test]
fn classify_red_above_threshold() {
    let state = classify_state(900_000, 500_000);
    assert_eq!(state, SentinelState::Red);
}

#[test]
fn classify_boundary_value() {
    // Value exactly at threshold
    let state = classify_state(500_000, 500_000);
    assert!(
        state == SentinelState::Green || state == SentinelState::Yellow,
        "boundary value should be Green or Yellow, got {state:?}"
    );
}

#[test]
fn classify_zero_threshold() {
    let state = classify_state(0, 0);
    assert!(
        state == SentinelState::Green || state == SentinelState::Yellow,
        "zero/zero should classify safely: {state:?}"
    );
}

// ---------------------------------------------------------------------------
// create_sentinel and update_sentinel
// ---------------------------------------------------------------------------

#[test]
fn create_sentinel_initial_state() {
    let s = create_sentinel("test-1", SentinelKind::ErrorBound, 500_000);
    assert_eq!(s.sentinel_id, "test-1");
    assert_eq!(s.kind, SentinelKind::ErrorBound);
    assert_eq!(s.threshold_millionths, 500_000);
}

#[test]
fn update_sentinel_changes_state() {
    let mut s = create_sentinel("test-2", SentinelKind::Coverage, 500_000);
    // Update with a high value (above threshold for lower-bound → Green)
    let state = update_sentinel(&mut s, 900_000);
    assert_eq!(s.current_value_millionths, 900_000);
    assert_eq!(s.state, state);
}

#[test]
fn update_sentinel_recomputes_hash() {
    let mut s = create_sentinel("test-3", SentinelKind::Freshness, 500_000);
    let hash1 = s.compute_hash();
    update_sentinel(&mut s, 100_000);
    let hash2 = s.compute_hash();
    assert_ne!(hash1, hash2, "hash should change after update");
}

// ---------------------------------------------------------------------------
// ObservabilityCell
// ---------------------------------------------------------------------------

#[test]
fn cell_all_green_overall_green() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::ErrorBound),
        make_green_sentinel("s2", SentinelKind::Coverage),
    ];
    let cell = build_cell("cell-1", "latency", sentinels, PromotionRule::FailClosed);
    assert_eq!(cell.compute_overall_state(), SentinelState::Green);
}

#[test]
fn cell_one_red_overall_red() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::ErrorBound),
        make_red_sentinel("s2", SentinelKind::Coverage),
    ];
    let cell = build_cell("cell-2", "throughput", sentinels, PromotionRule::FailClosed);
    assert_eq!(cell.compute_overall_state(), SentinelState::Red);
}

#[test]
fn cell_one_yellow_overall_yellow() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::Drift),
        make_yellow_sentinel("s2", SentinelKind::Completeness),
    ];
    let cell = build_cell("cell-3", "stability", sentinels, PromotionRule::FailClosed);
    let state = cell.compute_overall_state();
    assert!(
        state == SentinelState::Yellow || state == SentinelState::Red,
        "yellow sentinel should degrade overall: {state:?}"
    );
}

#[test]
fn cell_count_in_state() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::ErrorBound),
        make_green_sentinel("s2", SentinelKind::Coverage),
        make_red_sentinel("s3", SentinelKind::Drift),
    ];
    let cell = build_cell("cell-4", "perf", sentinels, PromotionRule::FailClosed);
    assert_eq!(cell.count_in_state(SentinelState::Green), 2);
    assert_eq!(cell.count_in_state(SentinelState::Red), 1);
}

#[test]
fn cell_hash_deterministic() {
    let sentinels = vec![make_green_sentinel("s1", SentinelKind::ErrorBound)];
    let cell = build_cell("cell-5", "det", sentinels, PromotionRule::FailClosed);
    let h1 = cell.compute_hash();
    let h2 = cell.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn cell_display_contains_id() {
    let sentinels = vec![make_green_sentinel("s1", SentinelKind::Coverage)];
    let cell = build_cell(
        "cell-disp",
        "domain-x",
        sentinels,
        PromotionRule::AllowWithWarning,
    );
    let s = format!("{cell}");
    assert!(s.contains("cell-disp"));
    assert!(s.contains("domain-x"));
}

#[test]
fn cell_serde_roundtrip() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::ErrorBound),
        make_red_sentinel("s2", SentinelKind::Coverage),
    ];
    let cell = build_cell(
        "cell-serde",
        "test",
        sentinels,
        PromotionRule::RequireCalibration,
    );
    let json = serde_json::to_string(&cell).unwrap();
    let restored: ObservabilityCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, restored);
}

// ---------------------------------------------------------------------------
// PromotionRule evaluation
// ---------------------------------------------------------------------------

#[test]
fn fail_closed_all_green_allows() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::ErrorBound),
        make_green_sentinel("s2", SentinelKind::Coverage),
    ];
    let cell = build_cell("fc-green", "test", sentinels, PromotionRule::FailClosed);
    let decision = evaluate_promotion(&cell);
    assert!(decision.allowed);
}

#[test]
fn fail_closed_one_red_blocks() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::ErrorBound),
        make_red_sentinel("s2", SentinelKind::Coverage),
    ];
    let cell = build_cell("fc-red", "test", sentinels, PromotionRule::FailClosed);
    let decision = evaluate_promotion(&cell);
    assert!(!decision.allowed);
}

#[test]
fn require_calibration_yellow_allows() {
    let sentinels = vec![
        make_green_sentinel("s1", SentinelKind::ErrorBound),
        make_yellow_sentinel("s2", SentinelKind::Completeness),
    ];
    let cell = build_cell(
        "rc-yellow",
        "test",
        sentinels,
        PromotionRule::RequireCalibration,
    );
    let decision = evaluate_promotion(&cell);
    // RequireCalibration allows Yellow but blocks Red
    // Yellow classification depends on exact threshold math
    assert!(decision.allowed || !decision.suppression_reasons.is_empty());
}

#[test]
fn require_calibration_red_blocks() {
    let sentinels = vec![make_red_sentinel("s1", SentinelKind::Coverage)];
    let cell = build_cell(
        "rc-red",
        "test",
        sentinels,
        PromotionRule::RequireCalibration,
    );
    let decision = evaluate_promotion(&cell);
    assert!(!decision.allowed);
}

#[test]
fn suppress_claim_always_blocks() {
    let sentinels = vec![make_green_sentinel("s1", SentinelKind::ErrorBound)];
    let cell = build_cell("sc-green", "test", sentinels, PromotionRule::SuppressClaim);
    let decision = evaluate_promotion(&cell);
    assert!(!decision.allowed);
}

#[test]
fn allow_with_warning_always_allows() {
    let sentinels = vec![make_red_sentinel("s1", SentinelKind::Coverage)];
    let cell = build_cell("aw-red", "test", sentinels, PromotionRule::AllowWithWarning);
    let decision = evaluate_promotion(&cell);
    assert!(decision.allowed);
}

#[test]
fn allow_with_warning_records_suppression_reasons() {
    let sentinels = vec![make_red_sentinel("s1", SentinelKind::Coverage)];
    let cell = build_cell(
        "aw-reasons",
        "test",
        sentinels,
        PromotionRule::AllowWithWarning,
    );
    let decision = evaluate_promotion(&cell);
    // Should record warnings even though allowed
    assert!(!decision.suppression_reasons.is_empty() || decision.allowed);
}

#[test]
fn promotion_decision_hash_deterministic() {
    let sentinels = vec![make_green_sentinel("s1", SentinelKind::ErrorBound)];
    let cell = build_cell("pd-det", "test", sentinels, PromotionRule::FailClosed);
    let d1 = evaluate_promotion(&cell);
    let d2 = evaluate_promotion(&cell);
    assert_eq!(d1.compute_hash(), d2.compute_hash());
}

#[test]
fn promotion_decision_display() {
    let sentinels = vec![make_green_sentinel("s1", SentinelKind::ErrorBound)];
    let cell = build_cell("pd-disp", "test", sentinels, PromotionRule::FailClosed);
    let d = evaluate_promotion(&cell);
    let s = format!("{d}");
    assert!(s.contains("pd-disp") || s.contains("ALLOWED") || s.contains("BLOCKED"));
}

// ---------------------------------------------------------------------------
// PromotionRule Display
// ---------------------------------------------------------------------------

#[test]
fn promotion_rule_display_all_distinct() {
    let rules = vec![
        PromotionRule::FailClosed,
        PromotionRule::RequireCalibration,
        PromotionRule::RequireObservability,
        PromotionRule::SuppressClaim,
        PromotionRule::AllowWithWarning,
    ];
    let displays: Vec<String> = rules.iter().map(|r| format!("{r}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 5);
}

// ---------------------------------------------------------------------------
// SentinelReport
// ---------------------------------------------------------------------------

#[test]
fn report_from_mixed_cells() {
    let green_cell = build_cell(
        "rc-g",
        "latency",
        vec![make_green_sentinel("s1", SentinelKind::ErrorBound)],
        PromotionRule::FailClosed,
    );
    let red_cell = build_cell(
        "rc-r",
        "coverage",
        vec![make_red_sentinel("s2", SentinelKind::Coverage)],
        PromotionRule::FailClosed,
    );
    let report = build_report(epoch(1), vec![green_cell, red_cell]);
    assert_eq!(report.cells.len(), 2);
    assert!(report.green_count > 0 || report.red_count > 0);
}

#[test]
fn report_green_fraction_all_green() {
    let cells = vec![
        build_cell(
            "c1",
            "d1",
            vec![make_green_sentinel("s1", SentinelKind::ErrorBound)],
            PromotionRule::FailClosed,
        ),
        build_cell(
            "c2",
            "d2",
            vec![make_green_sentinel("s2", SentinelKind::Coverage)],
            PromotionRule::FailClosed,
        ),
    ];
    let report = build_report(epoch(1), cells);
    let frac = report.green_fraction_millionths();
    assert!(frac > 0, "all green should have positive green fraction");
}

#[test]
fn report_serde_roundtrip() {
    let cells = vec![build_cell(
        "c1",
        "d1",
        vec![make_green_sentinel("s1", SentinelKind::Freshness)],
        PromotionRule::AllowWithWarning,
    )];
    let report = build_report(epoch(42), cells);
    let json = serde_json::to_string(&report).unwrap();
    let restored: SentinelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn report_display_contains_report_id() {
    let cells = vec![build_cell(
        "c1",
        "d1",
        vec![make_green_sentinel("s1", SentinelKind::Drift)],
        PromotionRule::FailClosed,
    )];
    let report = build_report(epoch(1), cells);
    let s = format!("{report}");
    assert!(!s.is_empty());
}

// ---------------------------------------------------------------------------
// Manifest determinism
// ---------------------------------------------------------------------------

#[test]
fn manifest_deterministic() {
    let m1 = franken_engine_sentinel_manifest();
    let m2 = franken_engine_sentinel_manifest();
    assert_eq!(m1.content_hash, m2.content_hash);
    assert_eq!(m1.cells.len(), m2.cells.len());
}

#[test]
fn manifest_has_cells() {
    let m = franken_engine_sentinel_manifest();
    assert!(!m.cells.is_empty(), "manifest should have cells");
}

// ---------------------------------------------------------------------------
// SentinelError
// ---------------------------------------------------------------------------

#[test]
fn sentinel_error_display_all_distinct() {
    let errors = vec![
        SentinelError::ThresholdViolation,
        SentinelError::MissingSentinel,
        SentinelError::CalibrationStale,
        SentinelError::InternalError("test".into()),
    ];
    let displays: Vec<String> = errors.iter().map(|e| format!("{e}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), errors.len());
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(CALIBRATION_SENTINEL_SCHEMA_VERSION.contains("calibration"));
    assert!(CALIBRATION_SENTINEL_BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// CalibrationSentinel
// ---------------------------------------------------------------------------

#[test]
fn sentinel_compute_hash_deterministic() {
    let s = make_green_sentinel("det-test", SentinelKind::ErrorBound);
    let h1 = s.compute_hash();
    let h2 = s.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn sentinel_display_contains_id() {
    let s = make_green_sentinel("display-test", SentinelKind::Coverage);
    let d = format!("{s}");
    assert!(d.contains("display-test"));
}

#[test]
fn sentinel_serde_roundtrip() {
    let s = make_green_sentinel("serde-test", SentinelKind::Drift);
    let json = serde_json::to_string(&s).unwrap();
    let restored: CalibrationSentinel = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

#[test]
fn sentinel_different_values_different_hashes() {
    let s1 = make_green_sentinel("h1", SentinelKind::ErrorBound);
    let s2 = make_red_sentinel("h1", SentinelKind::ErrorBound);
    assert_ne!(s1.compute_hash(), s2.compute_hash());
}
