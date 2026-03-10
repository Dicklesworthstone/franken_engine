//! Integration tests for nitrosketch_telemetry module: weighted sketch updates,
//! site inventories, exact-shadow calibration, and sampling strategies.

use frankenengine_engine::nitrosketch_telemetry::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: u64 = 1_000_000;

fn make_site(id: &str, kind: SketchKind) -> TelemetrySite {
    create_site(id, &format!("test/{}", id), kind, MILLION, 100_000)
}

fn make_site_with_budget(id: &str, budget: u64) -> TelemetrySite {
    create_site(id, &format!("test/{}", id), SketchKind::CountMin, MILLION, budget)
}

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

// ---------------------------------------------------------------------------
// SketchKind
// ---------------------------------------------------------------------------

#[test]
fn test_sketch_kind_all_variants_and_ordering() {
    let all = SketchKind::all();
    assert_eq!(all.len(), 6);
    assert_eq!(all[0], SketchKind::CountMin);
    assert_eq!(all[5], SketchKind::TopK);
    // Verify sorting stability
    let mut shuffled = vec![
        SketchKind::TopK,
        SketchKind::CountMin,
        SketchKind::Histogram,
        SketchKind::Quantile,
        SketchKind::HeavyHitter,
        SketchKind::FrequencyMoment,
    ];
    shuffled.sort();
    assert_eq!(shuffled, all.to_vec());
}

#[test]
fn test_sketch_kind_display_and_serde() {
    for kind in SketchKind::all() {
        assert_eq!(kind.as_str(), kind.to_string());
        let json = serde_json::to_string(kind).unwrap();
        let back: SketchKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// SamplingStrategy
// ---------------------------------------------------------------------------

#[test]
fn test_sampling_strategy_display_and_serde() {
    let strategies = [
        (SamplingStrategy::Deterministic, "deterministic"),
        (SamplingStrategy::ReplayStable, "replay_stable"),
        (SamplingStrategy::PriorityBased, "priority_based"),
        (SamplingStrategy::BudgetAdaptive, "budget_adaptive"),
    ];
    for (s, expected_str) in &strategies {
        assert_eq!(s.as_str(), *expected_str);
        assert_eq!(s.to_string(), *expected_str);
        let json = serde_json::to_string(s).unwrap();
        let back: SamplingStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// TelemetrySite construction and methods
// ---------------------------------------------------------------------------

#[test]
fn test_create_site_populates_all_fields() {
    let site = create_site("perf_counter", "/runtime/perf", SketchKind::Histogram, 750_000, 5000);
    assert_eq!(site.site_id, "perf_counter");
    assert_eq!(site.path, "/runtime/perf");
    assert_eq!(site.sketch_kind, SketchKind::Histogram);
    assert_eq!(site.sampling_rate_millionths, 750_000);
    assert_eq!(site.budget_remaining, 5000);
}

#[test]
fn test_site_has_budget() {
    assert!(make_site_with_budget("hb1", 1).has_budget());
    assert!(!make_site_with_budget("hb2", 0).has_budget());
}

#[test]
fn test_site_budget_consumed_millionths_cases() {
    // No budget consumed
    let site_full = make_site_with_budget("bc1", 500);
    assert_eq!(site_full.budget_consumed_millionths(500), 0);

    // Half consumed
    let mut site_half = make_site_with_budget("bc2", 1000);
    site_half.budget_remaining = 500;
    assert_eq!(site_half.budget_consumed_millionths(1000), 500_000);

    // Fully consumed
    let mut site_empty = make_site_with_budget("bc3", 1000);
    site_empty.budget_remaining = 0;
    assert_eq!(site_empty.budget_consumed_millionths(1000), MILLION);

    // Zero original budget
    let site_zero = make_site_with_budget("bc4", 0);
    assert_eq!(site_zero.budget_consumed_millionths(0), MILLION);
}

#[test]
fn test_site_display_format() {
    let site = create_site("gc_pause", "/gc/pause", SketchKind::Quantile, 500_000, 42);
    let display = site.to_string();
    assert!(display.contains("gc_pause"));
    assert!(display.contains("quantile"));
    assert!(display.contains("500000"));
    assert!(display.contains("42"));
}

#[test]
fn test_site_serde_round_trip() {
    let site = make_site("serde_site", SketchKind::FrequencyMoment);
    let json = serde_json::to_string(&site).unwrap();
    let back: TelemetrySite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

// ---------------------------------------------------------------------------
// SketchUpdate
// ---------------------------------------------------------------------------

#[test]
fn test_sketch_update_display_and_serde() {
    let update = SketchUpdate {
        site_id: "site_alpha".into(),
        key: "opcode_add".into(),
        weight_millionths: 2_000_000,
        timestamp_epoch: 99,
    };
    let s = update.to_string();
    assert!(s.contains("site_alpha"));
    assert!(s.contains("opcode_add"));
    assert!(s.contains("2000000"));

    let json = serde_json::to_string(&update).unwrap();
    let back: SketchUpdate = serde_json::from_str(&json).unwrap();
    assert_eq!(update, back);
}

// ---------------------------------------------------------------------------
// SiteInventory: build, find, recompute
// ---------------------------------------------------------------------------

#[test]
fn test_build_inventory_sorts_by_site_id() {
    let sites = vec![
        make_site("zeta", SketchKind::TopK),
        make_site("alpha", SketchKind::CountMin),
        make_site("mu", SketchKind::Quantile),
    ];
    let inv = build_inventory(sites);
    let ids: Vec<&str> = inv.sites.iter().map(|s| s.site_id.as_str()).collect();
    assert_eq!(ids, vec!["alpha", "mu", "zeta"]);
}

#[test]
fn test_build_inventory_budget_and_active_counts() {
    let sites = vec![
        make_site_with_budget("a", 100),
        make_site_with_budget("b", 0),
        make_site_with_budget("c", 50),
    ];
    let inv = build_inventory(sites);
    assert_eq!(inv.total_budget, 150);
    assert_eq!(inv.active_sites, 2);
}

#[test]
fn test_inventory_find_site_and_find_site_mut() {
    let mut inv = build_inventory(vec![
        make_site_with_budget("find_me", 100),
        make_site("other", SketchKind::Histogram),
    ]);
    assert!(inv.find_site("find_me").is_some());
    assert!(inv.find_site("ghost").is_none());

    let site = inv.find_site_mut("find_me").unwrap();
    site.budget_remaining = 50;
    assert_eq!(inv.find_site("find_me").unwrap().budget_remaining, 50);
}

#[test]
fn test_inventory_content_hash_deterministic_regardless_of_input_order() {
    let inv1 = build_inventory(vec![
        make_site("x", SketchKind::CountMin),
        make_site("y", SketchKind::Quantile),
    ]);
    let inv2 = build_inventory(vec![
        make_site("y", SketchKind::Quantile),
        make_site("x", SketchKind::CountMin),
    ]);
    assert_eq!(inv1.content_hash, inv2.content_hash);
    assert_eq!(inv1.inventory_id, inv2.inventory_id);
}

#[test]
fn test_inventory_recompute_hash_updates_aggregates() {
    let mut inv = build_inventory(vec![
        make_site_with_budget("a", 100),
        make_site_with_budget("b", 200),
    ]);
    inv.sites[0].budget_remaining = 0;
    inv.recompute_hash();
    assert_eq!(inv.total_budget, 200);
    assert_eq!(inv.active_sites, 1);
}

#[test]
fn test_inventory_display_format() {
    let inv = build_inventory(vec![
        make_site("p", SketchKind::CountMin),
        make_site("q", SketchKind::Histogram),
    ]);
    let s = inv.to_string();
    assert!(s.contains("inventory:"));
    assert!(s.contains("sites=2"));
    assert!(s.contains("active=2"));
}

#[test]
fn test_inventory_serde_round_trip() {
    let inv = build_inventory(vec![
        make_site("s1", SketchKind::CountMin),
        make_site("s2", SketchKind::TopK),
    ]);
    let json = serde_json::to_string(&inv).unwrap();
    let back: SiteInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn test_build_empty_inventory() {
    let inv = build_inventory(vec![]);
    assert_eq!(inv.sites.len(), 0);
    assert_eq!(inv.total_budget, 0);
    assert_eq!(inv.active_sites, 0);
    assert!(validate_inventory(&inv).is_ok());
}

// ---------------------------------------------------------------------------
// record_update
// ---------------------------------------------------------------------------

#[test]
fn test_record_update_decrements_budget_and_returns_correct_fields() {
    let mut site = make_site_with_budget("ru1", 10);
    let update = record_update(&mut site, "key_a", MILLION).unwrap();
    assert_eq!(site.budget_remaining, 9);
    assert_eq!(update.site_id, "ru1");
    assert_eq!(update.key, "key_a");
    assert_eq!(update.weight_millionths, MILLION);
}

#[test]
fn test_record_update_exhausted_budget_returns_error() {
    let mut site = make_site_with_budget("ru2", 0);
    assert_eq!(record_update(&mut site, "key", MILLION), Err(TelemetryError::BudgetExhausted));
}

#[test]
fn test_record_update_drains_full_budget() {
    let budget = 5u64;
    let mut site = make_site_with_budget("ru3", budget);
    for i in 0..budget {
        assert!(record_update(&mut site, &format!("k{}", i), MILLION).is_ok());
    }
    assert_eq!(site.budget_remaining, 0);
    assert!(record_update(&mut site, "overflow", MILLION).is_err());
}

// ---------------------------------------------------------------------------
// UpdateAccumulator
// ---------------------------------------------------------------------------

#[test]
fn test_accumulator_new_is_empty() {
    let acc = UpdateAccumulator::new("acc_site");
    assert_eq!(acc.site_id, "acc_site");
    assert_eq!(acc.update_count, 0);
    assert_eq!(acc.total_weight_millionths, 0);
    assert!(acc.weights.is_empty());
}

#[test]
fn test_accumulator_add_merges_and_separates_keys() {
    let mut acc = UpdateAccumulator::new("acc1");
    acc.add("opcode_add", 100);
    acc.add("opcode_add", 250);
    acc.add("opcode_sub", 300);
    assert_eq!(acc.update_count, 3);
    assert_eq!(acc.weights.len(), 2);
    assert_eq!(acc.weights[0].1, 350); // merged opcode_add
    assert_eq!(acc.weights[1].1, 300); // opcode_sub
    assert_eq!(acc.total_weight_millionths, 650);
}

#[test]
fn test_accumulator_drain_returns_updates_and_resets() {
    let mut acc = UpdateAccumulator::new("acc3");
    acc.add("k1", 100);
    acc.add("k2", 200);
    let updates = acc.drain(77);
    assert_eq!(updates.len(), 2);
    assert!(updates.iter().all(|u| u.timestamp_epoch == 77));
    assert!(updates.iter().all(|u| u.site_id == "acc3"));
    assert_eq!(acc.update_count, 0);
    assert_eq!(acc.total_weight_millionths, 0);
    assert!(acc.weights.is_empty());

    // Draining again yields empty
    assert!(acc.drain(99).is_empty());
}

// ---------------------------------------------------------------------------
// evaluate_sampling
// ---------------------------------------------------------------------------

#[test]
fn test_deterministic_sampling_period_acceptance() {
    // 50% rate => period = 2
    let accepted = evaluate_sampling(SamplingStrategy::Deterministic, 500_000, "key", MILLION, 0, 100, 100);
    assert!(accepted.accepted);
    assert_eq!(accepted.adjusted_weight_millionths, MILLION * 2);
    assert_eq!(accepted.strategy, SamplingStrategy::Deterministic);

    let rejected = evaluate_sampling(SamplingStrategy::Deterministic, 500_000, "key", MILLION, 1, 100, 100);
    assert!(!rejected.accepted);
}

#[test]
fn test_deterministic_sampling_full_rate_accepts_all() {
    for seq in 0..10 {
        let d = evaluate_sampling(SamplingStrategy::Deterministic, MILLION, "key", MILLION, seq, 100, 100);
        assert!(d.accepted);
    }
}

#[test]
fn test_replay_stable_consistency_and_full_rate() {
    // Same key produces same decision regardless of other params
    let d1 = evaluate_sampling(SamplingStrategy::ReplayStable, MILLION, "stable_key", MILLION, 0, 100, 100);
    let d2 = evaluate_sampling(SamplingStrategy::ReplayStable, MILLION, "stable_key", MILLION, 999, 50, 100);
    assert_eq!(d1.accepted, d2.accepted);

    // Full rate always accepts
    let d3 = evaluate_sampling(SamplingStrategy::ReplayStable, MILLION, "any_key", MILLION, 0, 100, 100);
    assert!(d3.accepted);
}

#[test]
fn test_priority_based_weight_threshold() {
    // threshold = MILLION - 500_000 = 500_000
    let high = evaluate_sampling(SamplingStrategy::PriorityBased, 500_000, "key", MILLION, 0, 100, 100);
    assert!(high.accepted);
    assert_eq!(high.adjusted_weight_millionths, MILLION);

    let low = evaluate_sampling(SamplingStrategy::PriorityBased, 500_000, "key", 100, 0, 100, 100);
    assert!(!low.accepted);
}

#[test]
fn test_budget_adaptive_zero_budget_rejects() {
    let d1 = evaluate_sampling(SamplingStrategy::BudgetAdaptive, MILLION, "key", MILLION, 0, 0, 100);
    assert!(!d1.accepted);

    let d2 = evaluate_sampling(SamplingStrategy::BudgetAdaptive, MILLION, "key", MILLION, 0, 0, 0);
    assert!(!d2.accepted);
}

// ---------------------------------------------------------------------------
// record_update_with_sampling
// ---------------------------------------------------------------------------

#[test]
fn test_record_with_sampling_accept_reject_and_exhausted() {
    // Accepted: consumes budget
    let mut site1 = make_site_with_budget("rws1", 100);
    site1.sampling_rate_millionths = MILLION;
    let result1 = record_update_with_sampling(&mut site1, SamplingStrategy::Deterministic, "key", MILLION, 0, 100);
    assert!(result1.unwrap().is_some());
    assert_eq!(site1.budget_remaining, 99);

    // Rejected: preserves budget
    let mut site2 = make_site_with_budget("rws2", 100);
    site2.sampling_rate_millionths = 500_000;
    let result2 = record_update_with_sampling(&mut site2, SamplingStrategy::Deterministic, "key", MILLION, 1, 100);
    assert!(result2.unwrap().is_none());
    assert_eq!(site2.budget_remaining, 100);

    // Exhausted: returns error
    let mut site3 = make_site_with_budget("rws3", 0);
    site3.sampling_rate_millionths = MILLION;
    let result3 = record_update_with_sampling(&mut site3, SamplingStrategy::Deterministic, "key", MILLION, 0, 100);
    assert_eq!(result3, Err(TelemetryError::BudgetExhausted));
}

// ---------------------------------------------------------------------------
// Inventory management: add, remove, reset
// ---------------------------------------------------------------------------

#[test]
fn test_add_site_to_inventory_maintains_sort() {
    let mut inv = build_inventory(vec![
        make_site("b_site", SketchKind::CountMin),
        make_site("d_site", SketchKind::Histogram),
    ]);
    add_site_to_inventory(&mut inv, make_site("c_site", SketchKind::Quantile)).unwrap();
    let ids: Vec<&str> = inv.sites.iter().map(|s| s.site_id.as_str()).collect();
    assert_eq!(ids, vec!["b_site", "c_site", "d_site"]);
}

#[test]
fn test_remove_site_from_inventory() {
    let mut inv = build_inventory(vec![
        make_site("rem_a", SketchKind::CountMin),
        make_site("rem_b", SketchKind::Histogram),
    ]);
    let removed = remove_site_from_inventory(&mut inv, "rem_a").unwrap();
    assert_eq!(removed.site_id, "rem_a");
    assert_eq!(inv.sites.len(), 1);
    assert!(inv.find_site("rem_a").is_none());

    // Missing site returns error
    assert_eq!(remove_site_from_inventory(&mut inv, "ghost"), Err(TelemetryError::SiteNotFound));
}

#[test]
fn test_reset_all_budgets() {
    let mut inv = build_inventory(vec![
        make_site_with_budget("r1", 10),
        make_site_with_budget("r2", 0),
    ]);
    reset_all_budgets(&mut inv, 777);
    assert!(inv.sites.iter().all(|s| s.budget_remaining == 777));
    assert_eq!(inv.total_budget, 777 * 2);
    assert_eq!(inv.active_sites, 2);
}

// ---------------------------------------------------------------------------
// Inventory validation
// ---------------------------------------------------------------------------

#[test]
fn test_validate_inventory_valid_and_tampered() {
    let inv = build_inventory(vec![
        make_site("v1", SketchKind::CountMin),
        make_site("v2", SketchKind::Histogram),
    ]);
    assert!(validate_inventory(&inv).is_ok());

    let mut tampered = build_inventory(vec![make_site("tamper", SketchKind::CountMin)]);
    tampered.content_hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered_data");
    assert!(validate_inventory(&tampered).is_err());
}

// ---------------------------------------------------------------------------
// Calibration: calibrate_site
// ---------------------------------------------------------------------------

#[test]
fn test_calibrate_site_exact_match_and_both_zero() {
    let site = make_site("cal1", SketchKind::CountMin);
    let exact = calibrate_site(&site, 1000, 1000);
    assert_eq!(exact.relative_error_millionths, 0);
    assert!(exact.passed);

    let zero = calibrate_site(&site, 0, 0);
    assert_eq!(zero.relative_error_millionths, 0);
    assert!(zero.passed);
}

#[test]
fn test_calibrate_site_error_boundary_and_failure() {
    let site = make_site("cal2", SketchKind::CountMin);

    // 1% error passes
    let small = calibrate_site(&site, 1000, 1010);
    assert_eq!(small.relative_error_millionths, 10_000);
    assert!(small.passed);

    // Exactly at 5% threshold passes
    let boundary = calibrate_site(&site, 200, 190);
    assert_eq!(boundary.relative_error_millionths, 50_000);
    assert!(boundary.passed);

    // 50% error fails
    let large = calibrate_site(&site, 100, 150);
    assert_eq!(large.relative_error_millionths, 500_000);
    assert!(!large.passed);

    // exact=0, estimate>0 => 100% error
    let inf = calibrate_site(&site, 0, 500);
    assert_eq!(inf.relative_error_millionths, MILLION);
    assert!(!inf.passed);
}

#[test]
fn test_calibration_result_display_and_serde() {
    let site = make_site("cal_ds", SketchKind::Quantile);
    let result = calibrate_site(&site, 100, 95);
    let s = result.to_string();
    assert!(s.contains("cal_ds"));
    assert!(s.contains("exact=100"));
    assert!(s.contains("estimate=95"));

    let json = serde_json::to_string(&result).unwrap();
    let back: CalibrationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// CalibrationReport
// ---------------------------------------------------------------------------

#[test]
fn test_calibration_report_mean_max_and_pass_status() {
    let site_a = make_site("rpt_a", SketchKind::CountMin);
    let site_b = make_site("rpt_b", SketchKind::CountMin);
    let results = vec![
        calibrate_site(&site_a, 1000, 1010), // 10_000 error
        calibrate_site(&site_b, 1000, 1050), // 50_000 error
    ];
    let report = build_calibration_report(test_epoch(), results);
    assert_eq!(report.mean_error_millionths, 30_000);
    assert_eq!(report.max_error_millionths, 50_000);
    assert!(report.all_passed());
    assert_eq!(report.failure_count(), 0);
}

#[test]
fn test_calibration_report_failure_and_empty() {
    // Report with a failure
    let results = vec![
        calibrate_site(&make_site("ok", SketchKind::CountMin), 100, 100),
        calibrate_site(&make_site("bad", SketchKind::CountMin), 100, 200),
    ];
    let report = build_calibration_report(test_epoch(), results);
    assert!(!report.all_passed());
    assert_eq!(report.failure_count(), 1);

    // Empty report
    let empty = build_calibration_report(test_epoch(), vec![]);
    assert_eq!(empty.mean_error_millionths, 0);
    assert_eq!(empty.max_error_millionths, 0);
    assert!(empty.all_passed());
}

#[test]
fn test_calibration_report_display_and_serde() {
    let results = vec![calibrate_site(&make_site("d", SketchKind::CountMin), 100, 100)];
    let report = build_calibration_report(SecurityEpoch::from_raw(7), results);
    let s = report.to_string();
    assert!(s.contains("report:"));
    assert!(s.contains("all_passed=true"));

    let json = serde_json::to_string(&report).unwrap();
    let back: CalibrationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// calibrate_inventory
// ---------------------------------------------------------------------------

#[test]
fn test_calibrate_inventory_success_and_missing_site() {
    let inv = build_inventory(vec![
        make_site("ci_a", SketchKind::CountMin),
        make_site("ci_b", SketchKind::Quantile),
    ]);
    let report = calibrate_inventory(&inv, &[("ci_a", 100, 100), ("ci_b", 200, 198)], test_epoch()).unwrap();
    assert_eq!(report.results.len(), 2);
    assert!(report.all_passed());

    // Missing site
    let err = calibrate_inventory(&inv, &[("ghost", 100, 100)], test_epoch());
    assert_eq!(err, Err(TelemetryError::SiteNotFound));
}

// ---------------------------------------------------------------------------
// compute_sampling_rate
// ---------------------------------------------------------------------------

#[test]
fn test_compute_sampling_rate_edge_cases() {
    assert_eq!(compute_sampling_rate(100, 0), MILLION);
    assert_eq!(compute_sampling_rate(1000, 500), MILLION);
    assert_eq!(compute_sampling_rate(100, 100), MILLION);
    assert_eq!(compute_sampling_rate(50, 100), 500_000);
    assert_eq!(compute_sampling_rate(10, 100), 100_000);
}

// ---------------------------------------------------------------------------
// meets_quality_bar
// ---------------------------------------------------------------------------

#[test]
fn test_meets_quality_bar() {
    let pass_report = build_calibration_report(test_epoch(), vec![
        calibrate_site(&make_site("qb1", SketchKind::CountMin), 100, 100),
    ]);
    assert!(meets_quality_bar(&pass_report, 50_000));

    let fail_report = build_calibration_report(test_epoch(), vec![
        calibrate_site(&make_site("qb2", SketchKind::CountMin), 100, 200),
    ]);
    assert!(!meets_quality_bar(&fail_report, 50_000));

    // Passes per-site but mean error above custom threshold
    let marginal = build_calibration_report(test_epoch(), vec![
        calibrate_site(&make_site("qb3", SketchKind::CountMin), 1000, 1049),
    ]);
    assert!(!meets_quality_bar(&marginal, 10_000));
}

// ---------------------------------------------------------------------------
// TelemetryError
// ---------------------------------------------------------------------------

#[test]
fn test_telemetry_error_display_and_serde() {
    let errors = vec![
        (TelemetryError::SiteNotFound, "site not found"),
        (TelemetryError::BudgetExhausted, "budget exhausted"),
        (TelemetryError::CalibrationFailed, "calibration failed"),
        (TelemetryError::SketchOverflow, "sketch overflow"),
        (TelemetryError::InternalError("whoops".into()), "whoops"),
    ];
    for (e, expected_substr) in &errors {
        assert!(e.to_string().contains(expected_substr));
        let json = serde_json::to_string(e).unwrap();
        let back: TelemetryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// SamplingDecision and TelemetryManifestEntry serde
// ---------------------------------------------------------------------------

#[test]
fn test_sampling_decision_and_manifest_entry_serde() {
    let decision = SamplingDecision {
        accepted: true,
        adjusted_weight_millionths: 500_000,
        strategy: SamplingStrategy::ReplayStable,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: SamplingDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);

    let entry = TelemetryManifestEntry {
        site_id: "hot_loop".into(),
        description: "Hot loop entry counter".into(),
        sketch_kind: SketchKind::CountMin,
        strategy: SamplingStrategy::Deterministic,
        sampling_rate_millionths: MILLION,
    };
    let json2 = serde_json::to_string(&entry).unwrap();
    let back2: TelemetryManifestEntry = serde_json::from_str(&json2).unwrap();
    assert_eq!(entry, back2);
}

#[test]
fn test_compute_manifest_entries_matches_inventory() {
    let inv = build_inventory(vec![
        make_site("m1", SketchKind::CountMin),
        make_site("m2", SketchKind::Quantile),
        make_site("m3", SketchKind::TopK),
    ]);
    let entries = compute_manifest_entries(&inv);
    assert_eq!(entries.len(), 3);
    for (entry, site) in entries.iter().zip(inv.sites.iter()) {
        assert_eq!(entry.site_id, site.site_id);
        assert_eq!(entry.sketch_kind, site.sketch_kind);
        assert_eq!(entry.sampling_rate_millionths, site.sampling_rate_millionths);
    }
}

// ---------------------------------------------------------------------------
// franken_engine_telemetry_manifest
// ---------------------------------------------------------------------------

#[test]
fn test_franken_engine_manifest_properties_and_determinism() {
    let inv = franken_engine_telemetry_manifest();
    assert_eq!(inv.sites.len(), 8);
    assert_eq!(inv.active_sites, 8);
    assert!(inv.sites.iter().all(|s| s.has_budget()));

    // Sites sorted alphabetically
    let ids: Vec<&str> = inv.sites.iter().map(|s| s.site_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);

    // Validates cleanly
    assert!(validate_inventory(&inv).is_ok());

    // Deterministic across calls
    let inv2 = franken_engine_telemetry_manifest();
    assert_eq!(inv.content_hash, inv2.content_hash);
    assert_eq!(inv.inventory_id, inv2.inventory_id);
}

// ---------------------------------------------------------------------------
// End-to-end lifecycle scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_full_lifecycle_create_record_calibrate() {
    // 1. Create sites and build inventory
    let sites = vec![
        create_site("counter_a", "/a", SketchKind::CountMin, MILLION, 10),
        create_site("counter_b", "/b", SketchKind::Quantile, 500_000, 20),
    ];
    let mut inv = build_inventory(sites);
    assert!(validate_inventory(&inv).is_ok());

    // 2. Record some updates on site counter_a
    let site_a = inv.find_site_mut("counter_a").unwrap();
    for i in 0..5u64 {
        let update = record_update(site_a, &format!("key_{}", i), MILLION).unwrap();
        assert_eq!(update.site_id, "counter_a");
    }
    assert_eq!(inv.find_site("counter_a").unwrap().budget_remaining, 5);

    // 3. Recompute hash after mutations
    inv.recompute_hash();
    assert!(validate_inventory(&inv).is_ok());

    // 4. Calibrate the inventory
    let measurements = vec![("counter_a", 5u64, 5u64), ("counter_b", 100, 98)];
    let report = calibrate_inventory(&inv, &measurements, test_epoch()).unwrap();
    assert!(report.all_passed());
    assert!(meets_quality_bar(&report, 50_000));
}

#[test]
fn test_lifecycle_add_remove_sites_revalidate() {
    let mut inv = build_inventory(vec![make_site("orig_a", SketchKind::CountMin)]);
    assert!(validate_inventory(&inv).is_ok());

    add_site_to_inventory(&mut inv, make_site("orig_b", SketchKind::Histogram)).unwrap();
    assert_eq!(inv.sites.len(), 2);
    assert!(validate_inventory(&inv).is_ok());

    let removed = remove_site_from_inventory(&mut inv, "orig_a").unwrap();
    assert_eq!(removed.site_id, "orig_a");
    assert_eq!(inv.sites.len(), 1);
    assert!(validate_inventory(&inv).is_ok());
}
