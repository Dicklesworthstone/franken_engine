//! Enrichment integration tests for `nitrosketch_telemetry`.
//!
//! Supplements base tests with deeper coverage of: budget consumption edges,
//! inventory management (add/remove/validate), calibration report aggregation,
//! sampling strategy evaluation, UpdateAccumulator drain semantics,
//! manifest entry generation, quality bar checks, and Display formatting.

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

use std::collections::BTreeSet;

use frankenengine_engine::nitrosketch_telemetry::{
    CalibrationReport, CalibrationResult, SamplingStrategy, SketchKind, SketchUpdate,
    TelemetryError, TelemetryManifestEntry, TelemetrySite, UpdateAccumulator,
    add_site_to_inventory, build_calibration_report, build_inventory, calibrate_inventory,
    calibrate_site, compute_manifest_entries, compute_sampling_rate, create_site,
    evaluate_sampling, franken_engine_telemetry_manifest, meets_quality_bar, record_update,
    remove_site_from_inventory, reset_all_budgets, validate_inventory,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mk_site(id: &str, kind: SketchKind) -> TelemetrySite {
    create_site(id, &format!("test/{id}"), kind, 1_000_000, 100_000)
}

fn mk_site_budget(id: &str, budget: u64) -> TelemetrySite {
    create_site(
        id,
        &format!("test/{id}"),
        SketchKind::CountMin,
        1_000_000,
        budget,
    )
}

// ===========================================================================
// A. Budget consumption edges (5 tests)
// ===========================================================================

#[test]
fn enrichment_record_update_decrements_budget() {
    let mut site = mk_site_budget("s1", 10);
    let _ = record_update(&mut site, "k", 100).unwrap();
    assert_eq!(site.budget_remaining, 9);
}

#[test]
fn enrichment_record_update_exhausts_budget() {
    let mut site = mk_site_budget("s1", 1);
    let update = record_update(&mut site, "k", 100).unwrap();
    assert_eq!(update.site_id, "s1");
    assert_eq!(site.budget_remaining, 0);
    assert!(!site.has_budget());
}

#[test]
fn enrichment_record_update_zero_budget_fails() {
    let mut site = mk_site_budget("s1", 0);
    let result = record_update(&mut site, "k", 100);
    assert_eq!(result, Err(TelemetryError::BudgetExhausted));
}

#[test]
fn enrichment_budget_consumed_millionths_half() {
    let site = mk_site_budget("s1", 50_000);
    let consumed = site.budget_consumed_millionths(100_000);
    assert_eq!(consumed, 500_000, "50% consumed → 500_000 millionths");
}

#[test]
fn enrichment_budget_consumed_millionths_zero_original() {
    let site = mk_site_budget("s1", 0);
    let consumed = site.budget_consumed_millionths(0);
    assert_eq!(consumed, 1_000_000, "zero original budget → fully consumed");
}

// ===========================================================================
// B. Inventory management (7 tests)
// ===========================================================================

#[test]
fn enrichment_build_inventory_sorts_by_site_id() {
    let sites = vec![
        mk_site("z-site", SketchKind::TopK),
        mk_site("a-site", SketchKind::CountMin),
        mk_site("m-site", SketchKind::Quantile),
    ];
    let inv = build_inventory(sites);
    let ids: Vec<_> = inv.sites.iter().map(|s| s.site_id.as_str()).collect();
    assert_eq!(ids, vec!["a-site", "m-site", "z-site"]);
}

#[test]
fn enrichment_build_inventory_hash_deterministic() {
    let sites1 = vec![
        mk_site("a", SketchKind::CountMin),
        mk_site("b", SketchKind::Quantile),
    ];
    let sites2 = vec![
        mk_site("b", SketchKind::Quantile),
        mk_site("a", SketchKind::CountMin),
    ];
    let inv1 = build_inventory(sites1);
    let inv2 = build_inventory(sites2);
    assert_eq!(inv1.content_hash, inv2.content_hash);
}

#[test]
fn enrichment_add_site_to_inventory_increases_count() {
    let mut inv = build_inventory(vec![mk_site("a", SketchKind::CountMin)]);
    assert_eq!(inv.sites.len(), 1);
    add_site_to_inventory(&mut inv, mk_site("b", SketchKind::Quantile)).unwrap();
    assert_eq!(inv.sites.len(), 2);
}

#[test]
fn enrichment_remove_site_from_inventory_decreases_count() {
    let mut inv = build_inventory(vec![
        mk_site("a", SketchKind::CountMin),
        mk_site("b", SketchKind::Quantile),
    ]);
    let removed = remove_site_from_inventory(&mut inv, "a").unwrap();
    assert_eq!(removed.site_id, "a");
    assert_eq!(inv.sites.len(), 1);
}

#[test]
fn enrichment_remove_nonexistent_site_fails() {
    let mut inv = build_inventory(vec![mk_site("a", SketchKind::CountMin)]);
    let result = remove_site_from_inventory(&mut inv, "nonexistent");
    assert_eq!(result, Err(TelemetryError::SiteNotFound));
}

#[test]
fn enrichment_validate_inventory_passes_for_valid() {
    let inv = build_inventory(vec![
        mk_site("a", SketchKind::CountMin),
        mk_site("b", SketchKind::Quantile),
    ]);
    assert!(validate_inventory(&inv).is_ok());
}

#[test]
fn enrichment_validate_inventory_detects_hash_mismatch() {
    let mut inv = build_inventory(vec![mk_site("a", SketchKind::CountMin)]);
    // Mutate without recomputing hash
    inv.sites[0].budget_remaining = 0;
    let result = validate_inventory(&inv);
    assert!(result.is_err());
}

// ===========================================================================
// C. Calibration report aggregation (6 tests)
// ===========================================================================

#[test]
fn enrichment_calibrate_site_exact_match_passes() {
    let site = mk_site("s1", SketchKind::CountMin);
    let result = calibrate_site(&site, 1000, 1000);
    assert!(result.passed);
    assert_eq!(result.relative_error_millionths, 0);
}

#[test]
fn enrichment_calibrate_site_both_zero_passes() {
    let site = mk_site("s1", SketchKind::CountMin);
    let result = calibrate_site(&site, 0, 0);
    assert!(result.passed);
    assert_eq!(result.relative_error_millionths, 0);
}

#[test]
fn enrichment_calibrate_site_exact_zero_estimate_nonzero_fails() {
    let site = mk_site("s1", SketchKind::CountMin);
    let result = calibrate_site(&site, 0, 100);
    assert!(!result.passed);
    assert_eq!(result.relative_error_millionths, 1_000_000);
}

#[test]
fn enrichment_calibrate_site_within_threshold_passes() {
    let site = mk_site("s1", SketchKind::CountMin);
    // 4% error: |1000-960|/1000 = 40/1000 = 0.04 = 40_000 millionths
    let result = calibrate_site(&site, 1000, 960);
    assert!(result.passed, "4% error should be under 5% threshold");
    assert_eq!(result.relative_error_millionths, 40_000);
}

#[test]
fn enrichment_calibrate_site_over_threshold_fails() {
    let site = mk_site("s1", SketchKind::CountMin);
    // 10% error
    let result = calibrate_site(&site, 1000, 900);
    assert!(!result.passed, "10% error should exceed 5% threshold");
    assert_eq!(result.relative_error_millionths, 100_000);
}

#[test]
fn enrichment_build_calibration_report_stats() {
    let epoch = SecurityEpoch::from_raw(1);
    let results = vec![
        CalibrationResult {
            site_id: "s1".into(),
            exact_count: 1000,
            sketch_estimate: 1000,
            relative_error_millionths: 0,
            passed: true,
        },
        CalibrationResult {
            site_id: "s2".into(),
            exact_count: 1000,
            sketch_estimate: 950,
            relative_error_millionths: 50_000,
            passed: true,
        },
    ];
    let report = build_calibration_report(epoch, results);
    assert_eq!(report.mean_error_millionths, 25_000);
    assert_eq!(report.max_error_millionths, 50_000);
    assert!(report.all_passed());
    assert_eq!(report.failure_count(), 0);
}

// ===========================================================================
// D. Sampling strategy evaluation (7 tests)
// ===========================================================================

#[test]
fn enrichment_deterministic_sampling_accepts_every_event_at_full_rate() {
    let decision = evaluate_sampling(
        SamplingStrategy::Deterministic,
        1_000_000, // full rate
        "key",
        100,
        0, // event_sequence
        100_000,
        100_000,
    );
    assert!(decision.accepted);
}

#[test]
fn enrichment_deterministic_sampling_period_two() {
    // rate = 500_000 → period = 1_000_000/500_000 = 2
    let d0 = evaluate_sampling(
        SamplingStrategy::Deterministic,
        500_000,
        "k",
        100,
        0,
        1000,
        1000,
    );
    let d1 = evaluate_sampling(
        SamplingStrategy::Deterministic,
        500_000,
        "k",
        100,
        1,
        1000,
        1000,
    );
    let d2 = evaluate_sampling(
        SamplingStrategy::Deterministic,
        500_000,
        "k",
        100,
        2,
        1000,
        1000,
    );
    assert!(d0.accepted, "seq 0 should be accepted (0 % 2 == 0)");
    assert!(!d1.accepted, "seq 1 should be rejected (1 % 2 != 0)");
    assert!(d2.accepted, "seq 2 should be accepted (2 % 2 == 0)");
}

#[test]
fn enrichment_replay_stable_deterministic_for_same_key() {
    let d1 = evaluate_sampling(
        SamplingStrategy::ReplayStable,
        500_000,
        "same-key",
        100,
        0,
        1000,
        1000,
    );
    let d2 = evaluate_sampling(
        SamplingStrategy::ReplayStable,
        500_000,
        "same-key",
        100,
        0,
        1000,
        1000,
    );
    assert_eq!(
        d1.accepted, d2.accepted,
        "replay stable should be deterministic"
    );
}

#[test]
fn enrichment_priority_based_high_weight_accepted() {
    // threshold = 1_000_000 - 500_000 = 500_000, weight=1_000_000 >= 500_000 → accepted
    let decision = evaluate_sampling(
        SamplingStrategy::PriorityBased,
        500_000,
        "k",
        1_000_000,
        0,
        1000,
        1000,
    );
    assert!(decision.accepted);
}

#[test]
fn enrichment_priority_based_low_weight_rejected() {
    // threshold = 1_000_000 - 500_000 = 500_000, weight=100 < 500_000 → rejected
    let decision = evaluate_sampling(
        SamplingStrategy::PriorityBased,
        500_000,
        "k",
        100,
        0,
        1000,
        1000,
    );
    assert!(!decision.accepted);
}

#[test]
fn enrichment_budget_adaptive_zero_budget_rejects() {
    let decision = evaluate_sampling(
        SamplingStrategy::BudgetAdaptive,
        1_000_000,
        "k",
        100,
        0,
        0,
        1000,
    );
    assert!(
        !decision.accepted,
        "zero remaining budget → zero effective rate → always reject"
    );
}

#[test]
fn enrichment_sampling_zero_rate_deterministic_rejects_most() {
    // rate=0 → period=u64::MAX → only seq 0 accepted (0 % MAX == 0)
    let d0 = evaluate_sampling(SamplingStrategy::Deterministic, 0, "k", 100, 0, 1000, 1000);
    let d1 = evaluate_sampling(SamplingStrategy::Deterministic, 0, "k", 100, 1, 1000, 1000);
    assert!(d0.accepted);
    assert!(!d1.accepted);
}

// ===========================================================================
// E. UpdateAccumulator (5 tests)
// ===========================================================================

#[test]
fn enrichment_accumulator_new_is_empty() {
    let acc = UpdateAccumulator::new("site-1");
    assert_eq!(acc.site_id, "site-1");
    assert_eq!(acc.update_count, 0);
    assert_eq!(acc.total_weight_millionths, 0);
    assert!(acc.weights.is_empty());
}

#[test]
fn enrichment_accumulator_add_single() {
    let mut acc = UpdateAccumulator::new("s");
    acc.add("key1", 100);
    assert_eq!(acc.update_count, 1);
    assert_eq!(acc.total_weight_millionths, 100);
    assert_eq!(acc.weights.len(), 1);
}

#[test]
fn enrichment_accumulator_add_same_key_merges() {
    let mut acc = UpdateAccumulator::new("s");
    acc.add("key1", 100);
    acc.add("key1", 200);
    assert_eq!(acc.update_count, 2);
    assert_eq!(acc.total_weight_millionths, 300);
    assert_eq!(acc.weights.len(), 1, "same key should merge");
    assert_eq!(acc.weights[0].1, 300);
}

#[test]
fn enrichment_accumulator_drain_returns_updates() {
    let mut acc = UpdateAccumulator::new("s");
    acc.add("a", 10);
    acc.add("b", 20);
    let updates = acc.drain(42);
    assert_eq!(updates.len(), 2);
    assert!(updates.iter().all(|u| u.timestamp_epoch == 42));
    assert!(updates.iter().all(|u| u.site_id == "s"));
    // After drain, accumulator is empty
    assert_eq!(acc.update_count, 0);
    assert_eq!(acc.total_weight_millionths, 0);
    assert!(acc.weights.is_empty());
}

#[test]
fn enrichment_accumulator_drain_empty_returns_empty() {
    let mut acc = UpdateAccumulator::new("s");
    let updates = acc.drain(1);
    assert!(updates.is_empty());
}

// ===========================================================================
// F. Manifest entry generation (3 tests)
// ===========================================================================

#[test]
fn enrichment_manifest_entries_count_matches_sites() {
    let inv = franken_engine_telemetry_manifest();
    let entries = compute_manifest_entries(&inv);
    assert_eq!(entries.len(), inv.sites.len());
}

#[test]
fn enrichment_manifest_entries_have_site_ids() {
    let inv = franken_engine_telemetry_manifest();
    let entries = compute_manifest_entries(&inv);
    let site_ids: BTreeSet<_> = inv.sites.iter().map(|s| &s.site_id).collect();
    let entry_ids: BTreeSet<_> = entries.iter().map(|e| &e.site_id).collect();
    assert_eq!(site_ids, entry_ids);
}

#[test]
fn enrichment_manifest_entry_serde_roundtrip() {
    let entry = TelemetryManifestEntry {
        site_id: "test".into(),
        description: "desc".into(),
        sketch_kind: SketchKind::CountMin,
        strategy: SamplingStrategy::Deterministic,
        sampling_rate_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: TelemetryManifestEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// G. Quality bar checks (3 tests)
// ===========================================================================

#[test]
fn enrichment_meets_quality_bar_all_passed_low_error() {
    let report = build_calibration_report(
        SecurityEpoch::from_raw(1),
        vec![CalibrationResult {
            site_id: "s1".into(),
            exact_count: 1000,
            sketch_estimate: 1000,
            relative_error_millionths: 0,
            passed: true,
        }],
    );
    assert!(meets_quality_bar(&report, 50_000));
}

#[test]
fn enrichment_meets_quality_bar_fails_when_not_all_passed() {
    let report = build_calibration_report(
        SecurityEpoch::from_raw(1),
        vec![CalibrationResult {
            site_id: "s1".into(),
            exact_count: 1000,
            sketch_estimate: 500,
            relative_error_millionths: 500_000,
            passed: false,
        }],
    );
    assert!(!meets_quality_bar(&report, 600_000));
}

#[test]
fn enrichment_meets_quality_bar_fails_when_mean_error_high() {
    let report = build_calibration_report(
        SecurityEpoch::from_raw(1),
        vec![CalibrationResult {
            site_id: "s1".into(),
            exact_count: 1000,
            sketch_estimate: 960,
            relative_error_millionths: 40_000,
            passed: true,
        }],
    );
    // Mean error is 40_000 but threshold is 10_000
    assert!(!meets_quality_bar(&report, 10_000));
}

// ===========================================================================
// H. Display formatting (5 tests)
// ===========================================================================

#[test]
fn enrichment_sketch_kind_display_distinct() {
    let mut displays = BTreeSet::new();
    for kind in SketchKind::all() {
        displays.insert(kind.to_string());
    }
    assert_eq!(displays.len(), SketchKind::all().len());
}

#[test]
fn enrichment_telemetry_site_display_contains_id() {
    let site = mk_site("my-site", SketchKind::CountMin);
    let display = format!("{site}");
    assert!(display.contains("my-site"));
    assert!(display.contains("count_min"));
}

#[test]
fn enrichment_sketch_update_display_contains_key() {
    let update = SketchUpdate {
        site_id: "s1".into(),
        key: "my-key".into(),
        weight_millionths: 100,
        timestamp_epoch: 42,
    };
    let display = format!("{update}");
    assert!(display.contains("my-key"));
    assert!(display.contains("s1"));
}

#[test]
fn enrichment_calibration_result_display_contains_site_id() {
    let result = CalibrationResult {
        site_id: "cal-site".into(),
        exact_count: 100,
        sketch_estimate: 95,
        relative_error_millionths: 50_000,
        passed: true,
    };
    let display = format!("{result}");
    assert!(display.contains("cal-site"));
}

#[test]
fn enrichment_telemetry_error_display_all_variants() {
    let errors = [
        TelemetryError::SiteNotFound,
        TelemetryError::BudgetExhausted,
        TelemetryError::CalibrationFailed,
        TelemetryError::SketchOverflow,
        TelemetryError::InternalError("test msg".into()),
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(
        displays.len(),
        errors.len(),
        "all error displays should be distinct"
    );
}

// ===========================================================================
// I. Compute sampling rate (4 tests)
// ===========================================================================

#[test]
fn enrichment_compute_sampling_rate_zero_events_returns_million() {
    assert_eq!(compute_sampling_rate(1000, 0), 1_000_000);
}

#[test]
fn enrichment_compute_sampling_rate_budget_exceeds_events() {
    assert_eq!(compute_sampling_rate(10_000, 5_000), 1_000_000);
}

#[test]
fn enrichment_compute_sampling_rate_half_budget() {
    // budget=500, expected=1000 → rate = 500/1000 = 0.5 = 500_000 millionths
    let rate = compute_sampling_rate(500, 1000);
    assert_eq!(rate, 500_000);
}

#[test]
fn enrichment_compute_sampling_rate_tenth_budget() {
    // budget=100, expected=1000 → rate = 100/1000 = 0.1 = 100_000 millionths
    let rate = compute_sampling_rate(100, 1000);
    assert_eq!(rate, 100_000);
}

// ===========================================================================
// J. Inventory-level calibration (4 tests)
// ===========================================================================

#[test]
fn enrichment_calibrate_inventory_all_exact() {
    let inv = build_inventory(vec![
        mk_site("a", SketchKind::CountMin),
        mk_site("b", SketchKind::Quantile),
    ]);
    let report = calibrate_inventory(
        &inv,
        &[("a", 100, 100), ("b", 200, 200)],
        SecurityEpoch::from_raw(1),
    )
    .unwrap();
    assert!(report.all_passed());
    assert_eq!(report.mean_error_millionths, 0);
    assert_eq!(report.max_error_millionths, 0);
}

#[test]
fn enrichment_calibrate_inventory_unknown_site_fails() {
    let inv = build_inventory(vec![mk_site("a", SketchKind::CountMin)]);
    let result = calibrate_inventory(
        &inv,
        &[("nonexistent", 100, 100)],
        SecurityEpoch::from_raw(1),
    );
    assert_eq!(result, Err(TelemetryError::SiteNotFound));
}

#[test]
fn enrichment_calibrate_inventory_report_id_has_prefix() {
    let inv = build_inventory(vec![mk_site("a", SketchKind::CountMin)]);
    let report = calibrate_inventory(&inv, &[("a", 100, 100)], SecurityEpoch::from_raw(1)).unwrap();
    assert!(report.report_id.starts_with("cal-"));
}

#[test]
fn enrichment_calibrate_inventory_report_serde_roundtrip() {
    let inv = build_inventory(vec![mk_site("a", SketchKind::CountMin)]);
    let report = calibrate_inventory(&inv, &[("a", 100, 95)], SecurityEpoch::from_raw(1)).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: CalibrationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

// ===========================================================================
// K. Reset budgets and franken_engine manifest (3 tests)
// ===========================================================================

#[test]
fn enrichment_reset_all_budgets_sets_new_budget() {
    let mut inv = build_inventory(vec![mk_site_budget("a", 10), mk_site_budget("b", 20)]);
    reset_all_budgets(&mut inv, 999);
    for site in &inv.sites {
        assert_eq!(site.budget_remaining, 999);
    }
}

#[test]
fn enrichment_franken_engine_manifest_valid() {
    let inv = franken_engine_telemetry_manifest();
    assert!(validate_inventory(&inv).is_ok());
    assert!(!inv.sites.is_empty());
    assert!(inv.inventory_id.starts_with("inv-"));
}

#[test]
fn enrichment_franken_engine_manifest_all_have_budget() {
    let inv = franken_engine_telemetry_manifest();
    for site in &inv.sites {
        assert!(site.has_budget());
    }
}
