//! Enrichment integration tests for `kernel_shift_monitor`.
//!
//! Covers: all enum variant serde roundtrips, Display/as_str uniqueness,
//! WorkloadDimension::ALL count, KernelKind::requires_bandwidth correctness,
//! ShiftVerdict recommends_reevaluation and is_concerning logic,
//! MonitorConfig default_for defaults, MmdResult::compute verdict derivation
//! (NoShift, MarginalShift, SignificantShift, exact thresholds),
//! MmdResult::is_significant/is_marginal edge cases, MonitorResult accessors,
//! AggregateShiftReport aggregation (all NoShift, mixed, all Abstained, empty),
//! coverage_millionths, significantly_shifted_dimensions, result_for lookup,
//! content hash determinism, MonitorAbstention tag uniqueness and snake_case,
//! WindowSummary serde roundtrip, and constant values.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::kernel_shift_monitor::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn default_config(dim: WorkloadDimension) -> MonitorConfig {
    MonitorConfig::default_for(dim)
}

fn make_measured(dim: WorkloadDimension, mmd: u64) -> MonitorResult {
    let config = default_config(dim);
    MonitorResult::Measured(MmdResult::compute(dim, mmd, &config, 256, 256))
}

fn make_abstained(dim: WorkloadDimension, reason: MonitorAbstention) -> MonitorResult {
    MonitorResult::Abstained {
        dimension: dim,
        reason,
    }
}

fn make_abstained_default(dim: WorkloadDimension) -> MonitorResult {
    make_abstained(dim, MonitorAbstention::UncalibratedBandwidth)
}

// ---------------------------------------------------------------------------
// 1. Constants have expected values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_version_value() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.kernel-shift-monitor.v1");
}

#[test]
fn enrichment_constants_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.8.6.1");
}

#[test]
fn enrichment_constants_component_value() {
    assert_eq!(COMPONENT, "kernel_shift_monitor");
}

#[test]
fn enrichment_constants_default_window_size() {
    assert_eq!(DEFAULT_WINDOW_SIZE, 256);
}

#[test]
fn enrichment_constants_min_window_size() {
    assert_eq!(MIN_WINDOW_SIZE, 32);
}

#[test]
fn enrichment_constants_default_mmd_threshold() {
    assert_eq!(DEFAULT_MMD_THRESHOLD, 100_000);
}

#[test]
fn enrichment_constants_max_monitors() {
    assert_eq!(MAX_MONITORS, 32);
}

#[test]
fn enrichment_constants_default_false_alarm_budget() {
    assert_eq!(DEFAULT_FALSE_ALARM_BUDGET, 50_000);
}

#[test]
fn enrichment_constants_window_size_ordering() {
    assert!(DEFAULT_WINDOW_SIZE >= MIN_WINDOW_SIZE);
    assert!(MIN_WINDOW_SIZE > 0);
}

// ---------------------------------------------------------------------------
// 2. WorkloadDimension::ALL has 8 elements
// ---------------------------------------------------------------------------

#[test]
fn enrichment_dimension_all_has_eight_elements() {
    assert_eq!(WorkloadDimension::ALL.len(), 8);
}

// ---------------------------------------------------------------------------
// 3. Display and as_str uniqueness for WorkloadDimension
// ---------------------------------------------------------------------------

#[test]
fn enrichment_dimension_as_str_all_unique() {
    let names: BTreeSet<&str> = WorkloadDimension::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(names.len(), 8);
}

#[test]
fn enrichment_dimension_display_matches_as_str() {
    for d in WorkloadDimension::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn enrichment_dimension_as_str_are_snake_case() {
    for d in WorkloadDimension::ALL {
        let s = d.as_str();
        assert!(!s.is_empty());
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "dimension as_str {s} should be snake_case"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. WorkloadDimension serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_dimension_serde_roundtrip_all_variants() {
    for d in WorkloadDimension::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: WorkloadDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back, "serde roundtrip failed for {d:?}");
    }
}

// ---------------------------------------------------------------------------
// 5. KernelKind::ALL count + Display uniqueness + serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_kernel_all_has_four_elements() {
    assert_eq!(KernelKind::ALL.len(), 4);
}

#[test]
fn enrichment_kernel_as_str_all_unique() {
    let names: BTreeSet<&str> = KernelKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), 4);
}

#[test]
fn enrichment_kernel_display_matches_as_str() {
    for k in KernelKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn enrichment_kernel_serde_roundtrip_all_variants() {
    for k in KernelKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: KernelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back, "serde roundtrip failed for {k:?}");
    }
}

// ---------------------------------------------------------------------------
// 6. KernelKind::requires_bandwidth correctness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_kernel_requires_bandwidth_gaussian() {
    assert!(KernelKind::Gaussian.requires_bandwidth());
}

#[test]
fn enrichment_kernel_requires_bandwidth_laplacian() {
    assert!(KernelKind::Laplacian.requires_bandwidth());
}

#[test]
fn enrichment_kernel_does_not_require_bandwidth_linear() {
    assert!(!KernelKind::Linear.requires_bandwidth());
}

#[test]
fn enrichment_kernel_does_not_require_bandwidth_polynomial() {
    assert!(!KernelKind::Polynomial.requires_bandwidth());
}

// ---------------------------------------------------------------------------
// 7. ShiftVerdict recommends_reevaluation and is_concerning logic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_all_has_four_elements() {
    assert_eq!(ShiftVerdict::ALL.len(), 4);
}

#[test]
fn enrichment_verdict_serde_roundtrip_all_variants() {
    for v in ShiftVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back, "serde roundtrip failed for {v:?}");
    }
}

#[test]
fn enrichment_verdict_as_str_all_unique() {
    let names: BTreeSet<&str> = ShiftVerdict::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(names.len(), 4);
}

#[test]
fn enrichment_verdict_display_matches_as_str() {
    for v in ShiftVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn enrichment_verdict_recommends_reevaluation_only_significant() {
    assert!(!ShiftVerdict::NoShift.recommends_reevaluation());
    assert!(!ShiftVerdict::MarginalShift.recommends_reevaluation());
    assert!(ShiftVerdict::SignificantShift.recommends_reevaluation());
    assert!(!ShiftVerdict::Inconclusive.recommends_reevaluation());
}

#[test]
fn enrichment_verdict_is_concerning_marginal_and_significant() {
    assert!(!ShiftVerdict::NoShift.is_concerning());
    assert!(ShiftVerdict::MarginalShift.is_concerning());
    assert!(ShiftVerdict::SignificantShift.is_concerning());
    assert!(!ShiftVerdict::Inconclusive.is_concerning());
}

// ---------------------------------------------------------------------------
// 8. MonitorAbstention tag values are snake_case and unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_abstention_tags_all_snake_case() {
    let reasons = vec![
        MonitorAbstention::InsufficientSamples {
            available: 5,
            required: 32,
        },
        MonitorAbstention::UncalibratedBandwidth,
        MonitorAbstention::EmptyReferenceDistribution,
        MonitorAbstention::IncompleteWindow {
            filled: 10,
            window_size: 256,
        },
        MonitorAbstention::DisabledByPolicy,
    ];
    for r in &reasons {
        let tag = r.tag();
        assert!(!tag.is_empty());
        assert!(
            tag.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "tag {tag} should be snake_case"
        );
    }
}

#[test]
fn enrichment_abstention_tags_all_unique() {
    let reasons = vec![
        MonitorAbstention::InsufficientSamples {
            available: 5,
            required: 32,
        },
        MonitorAbstention::UncalibratedBandwidth,
        MonitorAbstention::EmptyReferenceDistribution,
        MonitorAbstention::IncompleteWindow {
            filled: 10,
            window_size: 256,
        },
        MonitorAbstention::DisabledByPolicy,
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 5);
}

#[test]
fn enrichment_abstention_display_insufficient_samples() {
    let r = MonitorAbstention::InsufficientSamples {
        available: 12,
        required: 64,
    };
    let s = r.to_string();
    assert!(s.contains("12"), "display should contain available count");
    assert!(s.contains("64"), "display should contain required count");
}

#[test]
fn enrichment_abstention_display_incomplete_window() {
    let r = MonitorAbstention::IncompleteWindow {
        filled: 100,
        window_size: 256,
    };
    let s = r.to_string();
    assert!(s.contains("100"), "display should contain filled count");
    assert!(s.contains("256"), "display should contain window_size");
}

#[test]
fn enrichment_abstention_serde_roundtrip_all_variants() {
    let reasons = vec![
        MonitorAbstention::InsufficientSamples {
            available: 5,
            required: 32,
        },
        MonitorAbstention::UncalibratedBandwidth,
        MonitorAbstention::EmptyReferenceDistribution,
        MonitorAbstention::IncompleteWindow {
            filled: 10,
            window_size: 256,
        },
        MonitorAbstention::DisabledByPolicy,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: MonitorAbstention = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back, "serde roundtrip failed for {r:?}");
    }
}

// ---------------------------------------------------------------------------
// 9. MonitorConfig default_for uses correct defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_default_for_all_dimensions() {
    for d in WorkloadDimension::ALL {
        let c = MonitorConfig::default_for(*d);
        assert_eq!(c.dimension, *d);
        assert_eq!(c.kernel, KernelKind::Gaussian);
        assert_eq!(c.bandwidth_millionths, 500_000);
        assert_eq!(c.window_size, DEFAULT_WINDOW_SIZE);
        assert_eq!(c.mmd_threshold_millionths, DEFAULT_MMD_THRESHOLD);
        assert_eq!(c.marginal_threshold_millionths, DEFAULT_MMD_THRESHOLD / 2);
    }
}

#[test]
fn enrichment_config_marginal_less_than_significant_threshold() {
    let c = default_config(WorkloadDimension::ComputeIntensity);
    assert!(
        c.marginal_threshold_millionths < c.mmd_threshold_millionths,
        "marginal threshold must be less than significance threshold"
    );
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let c = default_config(WorkloadDimension::GcPressureProfile);
    let json = serde_json::to_string(&c).unwrap();
    let back: MonitorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// 10. MmdResult::compute verdict derivation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mmd_compute_below_marginal_is_no_shift() {
    let config = default_config(WorkloadDimension::ComputeIntensity);
    // marginal threshold = 50_000, so 10_000 is well below
    let r = MmdResult::compute(
        WorkloadDimension::ComputeIntensity,
        10_000,
        &config,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::NoShift);
    assert!(!r.is_significant());
    assert!(!r.is_marginal());
}

#[test]
fn enrichment_mmd_compute_between_marginal_and_significant_is_marginal() {
    let config = default_config(WorkloadDimension::AllocationPattern);
    // marginal = 50_000, significant = 100_000, so 75_000 is marginal
    let r = MmdResult::compute(
        WorkloadDimension::AllocationPattern,
        75_000,
        &config,
        128,
        128,
    );
    assert_eq!(r.verdict, ShiftVerdict::MarginalShift);
    assert!(!r.is_significant());
    assert!(r.is_marginal());
}

#[test]
fn enrichment_mmd_compute_above_significant_is_significant() {
    let config = default_config(WorkloadDimension::ModuleGraphShape);
    let r = MmdResult::compute(
        WorkloadDimension::ModuleGraphShape,
        200_000,
        &config,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::SignificantShift);
    assert!(r.is_significant());
    assert!(r.is_marginal()); // significant implies marginal
}

#[test]
fn enrichment_mmd_compute_zero_mmd_is_no_shift() {
    let config = default_config(WorkloadDimension::HostcallProfile);
    let r = MmdResult::compute(WorkloadDimension::HostcallProfile, 0, &config, 256, 256);
    assert_eq!(r.verdict, ShiftVerdict::NoShift);
}

// ---------------------------------------------------------------------------
// 11. MmdResult::is_significant and is_marginal edge cases (exact threshold)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mmd_exact_marginal_threshold_is_marginal() {
    let config = default_config(WorkloadDimension::StringOperationProfile);
    let r = MmdResult::compute(
        WorkloadDimension::StringOperationProfile,
        config.marginal_threshold_millionths,
        &config,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::MarginalShift);
    assert!(r.is_marginal());
    assert!(!r.is_significant());
}

#[test]
fn enrichment_mmd_one_below_marginal_threshold_is_no_shift() {
    let config = default_config(WorkloadDimension::ControlFlowComplexity);
    let r = MmdResult::compute(
        WorkloadDimension::ControlFlowComplexity,
        config.marginal_threshold_millionths - 1,
        &config,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::NoShift);
    assert!(!r.is_marginal());
}

#[test]
fn enrichment_mmd_exact_significant_threshold_is_significant() {
    let config = default_config(WorkloadDimension::IoSchedulingPattern);
    let r = MmdResult::compute(
        WorkloadDimension::IoSchedulingPattern,
        config.mmd_threshold_millionths,
        &config,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::SignificantShift);
    assert!(r.is_significant());
}

#[test]
fn enrichment_mmd_one_below_significant_threshold_is_marginal() {
    let config = default_config(WorkloadDimension::GcPressureProfile);
    let r = MmdResult::compute(
        WorkloadDimension::GcPressureProfile,
        config.mmd_threshold_millionths - 1,
        &config,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::MarginalShift);
    assert!(!r.is_significant());
    assert!(r.is_marginal());
}

#[test]
fn enrichment_mmd_serde_roundtrip() {
    let config = default_config(WorkloadDimension::ComputeIntensity);
    let r = MmdResult::compute(
        WorkloadDimension::ComputeIntensity,
        60_000,
        &config,
        100,
        200,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: MmdResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_mmd_compute_preserves_sample_counts() {
    let config = default_config(WorkloadDimension::AllocationPattern);
    let r = MmdResult::compute(
        WorkloadDimension::AllocationPattern,
        5_000,
        &config,
        99,
        201,
    );
    assert_eq!(r.reference_sample_count, 99);
    assert_eq!(r.live_sample_count, 201);
}

#[test]
fn enrichment_mmd_compute_preserves_kernel() {
    let config = default_config(WorkloadDimension::ComputeIntensity);
    let r = MmdResult::compute(
        WorkloadDimension::ComputeIntensity,
        5_000,
        &config,
        256,
        256,
    );
    assert_eq!(r.kernel, KernelKind::Gaussian);
}

// ---------------------------------------------------------------------------
// 12. MonitorResult::Measured vs Abstained accessor methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_monitor_result_measured_accessors() {
    let r = make_measured(WorkloadDimension::ComputeIntensity, 10_000);
    assert!(r.is_measured());
    assert!(!r.is_abstained());
    assert_eq!(r.dimension(), WorkloadDimension::ComputeIntensity);
    assert_eq!(r.verdict(), Some(ShiftVerdict::NoShift));
    assert_eq!(r.mmd_millionths(), Some(10_000));
}

#[test]
fn enrichment_monitor_result_abstained_accessors() {
    let r = make_abstained(
        WorkloadDimension::GcPressureProfile,
        MonitorAbstention::DisabledByPolicy,
    );
    assert!(!r.is_measured());
    assert!(r.is_abstained());
    assert_eq!(r.dimension(), WorkloadDimension::GcPressureProfile);
    assert_eq!(r.verdict(), None);
    assert_eq!(r.mmd_millionths(), None);
}

#[test]
fn enrichment_monitor_result_measured_significant_verdict() {
    let r = make_measured(WorkloadDimension::AllocationPattern, 200_000);
    assert_eq!(r.verdict(), Some(ShiftVerdict::SignificantShift));
}

#[test]
fn enrichment_monitor_result_measured_marginal_verdict() {
    let r = make_measured(WorkloadDimension::ModuleGraphShape, 75_000);
    assert_eq!(r.verdict(), Some(ShiftVerdict::MarginalShift));
}

#[test]
fn enrichment_monitor_result_serde_roundtrip_measured() {
    let r = make_measured(WorkloadDimension::HostcallProfile, 80_000);
    let json = serde_json::to_string(&r).unwrap();
    let back: MonitorResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_monitor_result_serde_roundtrip_abstained() {
    let r = make_abstained(
        WorkloadDimension::IoSchedulingPattern,
        MonitorAbstention::IncompleteWindow {
            filled: 50,
            window_size: 256,
        },
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: MonitorResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// 13. AggregateShiftReport with empty results -> NoShift verdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_empty_results_no_shift() {
    let report = AggregateShiftReport::new(epoch(), Vec::new());
    assert_eq!(report.aggregate_verdict, ShiftVerdict::NoShift);
    assert_eq!(report.monitor_count(), 0);
    assert_eq!(report.measured_count(), 0);
    assert_eq!(report.significant_count, 0);
    assert_eq!(report.marginal_count, 0);
    assert_eq!(report.abstained_count, 0);
    assert!(!report.recommends_reevaluation());
}

// ---------------------------------------------------------------------------
// 14. AggregateShiftReport with all NoShift
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_all_no_shift_verdict() {
    let results: Vec<_> = WorkloadDimension::ALL
        .iter()
        .map(|d| make_measured(*d, 5_000))
        .collect();
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.aggregate_verdict, ShiftVerdict::NoShift);
    assert_eq!(report.significant_count, 0);
    assert_eq!(report.marginal_count, 0);
    assert_eq!(report.abstained_count, 0);
    assert_eq!(report.monitor_count(), 8);
    assert_eq!(report.measured_count(), 8);
    assert!(!report.recommends_reevaluation());
}

// ---------------------------------------------------------------------------
// 15. AggregateShiftReport with mixed results
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_mixed_significant_wins() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 5_000), // NoShift
        make_measured(WorkloadDimension::AllocationPattern, 75_000), // Marginal
        make_measured(WorkloadDimension::ModuleGraphShape, 200_000), // Significant
        make_abstained_default(WorkloadDimension::HostcallProfile), // Abstained
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.aggregate_verdict, ShiftVerdict::SignificantShift);
    assert_eq!(report.significant_count, 1);
    assert_eq!(report.marginal_count, 1);
    assert_eq!(report.abstained_count, 1);
    assert_eq!(report.monitor_count(), 4);
    assert_eq!(report.measured_count(), 3);
    assert!(report.recommends_reevaluation());
}

#[test]
fn enrichment_aggregate_marginal_only_no_significant() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 5_000), // NoShift
        make_measured(WorkloadDimension::AllocationPattern, 60_000), // Marginal
        make_measured(WorkloadDimension::ModuleGraphShape, 70_000), // Marginal
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.aggregate_verdict, ShiftVerdict::MarginalShift);
    assert_eq!(report.marginal_count, 2);
    assert_eq!(report.significant_count, 0);
    assert!(!report.recommends_reevaluation());
}

// ---------------------------------------------------------------------------
// 16. AggregateShiftReport with all Abstained -> Inconclusive
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_all_abstained_inconclusive() {
    let results: Vec<_> = WorkloadDimension::ALL
        .iter()
        .map(|d| make_abstained_default(*d))
        .collect();
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.aggregate_verdict, ShiftVerdict::Inconclusive);
    assert_eq!(report.abstained_count, 8);
    assert_eq!(report.measured_count(), 0);
    assert!(!report.recommends_reevaluation());
}

// ---------------------------------------------------------------------------
// 17. AggregateShiftReport coverage_millionths
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_coverage_empty() {
    let report = AggregateShiftReport::new(epoch(), Vec::new());
    assert_eq!(report.coverage_millionths(), 0);
}

#[test]
fn enrichment_aggregate_coverage_all_measured() {
    let results: Vec<_> = WorkloadDimension::ALL
        .iter()
        .map(|d| make_measured(*d, 5_000))
        .collect();
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.coverage_millionths(), 1_000_000);
}

#[test]
fn enrichment_aggregate_coverage_half_measured() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 5_000),
        make_abstained_default(WorkloadDimension::AllocationPattern),
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.coverage_millionths(), 500_000);
}

#[test]
fn enrichment_aggregate_coverage_one_of_three() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 5_000),
        make_abstained_default(WorkloadDimension::AllocationPattern),
        make_abstained_default(WorkloadDimension::ModuleGraphShape),
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    // 1/3 = 333_333
    assert_eq!(report.coverage_millionths(), 333_333);
}

#[test]
fn enrichment_aggregate_coverage_none_measured() {
    let results = vec![
        make_abstained_default(WorkloadDimension::ComputeIntensity),
        make_abstained_default(WorkloadDimension::AllocationPattern),
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.coverage_millionths(), 0);
}

// ---------------------------------------------------------------------------
// 18. AggregateShiftReport significantly_shifted_dimensions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_shifted_dims_empty_when_no_shift() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 5_000),
        make_measured(WorkloadDimension::AllocationPattern, 10_000),
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    assert!(report.significantly_shifted_dimensions().is_empty());
}

#[test]
fn enrichment_aggregate_shifted_dims_returns_correct_set() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 200_000), // Significant
        make_measured(WorkloadDimension::AllocationPattern, 5_000),  // NoShift
        make_measured(WorkloadDimension::ModuleGraphShape, 150_000), // Significant
        make_measured(WorkloadDimension::HostcallProfile, 75_000),   // Marginal
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    let shifted = report.significantly_shifted_dimensions();
    assert_eq!(shifted.len(), 2);
    assert!(shifted.contains(&WorkloadDimension::ComputeIntensity));
    assert!(shifted.contains(&WorkloadDimension::ModuleGraphShape));
    assert!(!shifted.contains(&WorkloadDimension::AllocationPattern));
    assert!(!shifted.contains(&WorkloadDimension::HostcallProfile));
}

// ---------------------------------------------------------------------------
// 19. AggregateShiftReport result_for lookup
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_result_for_found() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 30_000),
        make_abstained_default(WorkloadDimension::GcPressureProfile),
    ];
    let report = AggregateShiftReport::new(epoch(), results);

    let r1 = report.result_for(WorkloadDimension::ComputeIntensity);
    assert!(r1.is_some());
    assert!(r1.unwrap().is_measured());

    let r2 = report.result_for(WorkloadDimension::GcPressureProfile);
    assert!(r2.is_some());
    assert!(r2.unwrap().is_abstained());
}

#[test]
fn enrichment_aggregate_result_for_not_found() {
    let results = vec![make_measured(WorkloadDimension::ComputeIntensity, 5_000)];
    let report = AggregateShiftReport::new(epoch(), results);
    assert!(
        report
            .result_for(WorkloadDimension::IoSchedulingPattern)
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// 20. Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_content_hash_deterministic_same_inputs() {
    let r1 = AggregateShiftReport::new(
        epoch(),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)],
    );
    let r2 = AggregateShiftReport::new(
        epoch(),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)],
    );
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_aggregate_content_hash_differs_with_different_mmd() {
    let r1 = AggregateShiftReport::new(
        epoch(),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)],
    );
    let r2 = AggregateShiftReport::new(
        epoch(),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 60_000)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_aggregate_content_hash_differs_with_different_epoch() {
    let r1 = AggregateShiftReport::new(
        SecurityEpoch::from_raw(1),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)],
    );
    let r2 = AggregateShiftReport::new(
        SecurityEpoch::from_raw(2),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_aggregate_content_hash_differs_with_different_dimension() {
    let r1 = AggregateShiftReport::new(
        epoch(),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)],
    );
    let r2 = AggregateShiftReport::new(
        epoch(),
        vec![make_measured(WorkloadDimension::AllocationPattern, 50_000)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_aggregate_content_hash_differs_measured_vs_abstained() {
    let r1 = AggregateShiftReport::new(
        epoch(),
        vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)],
    );
    let r2 = AggregateShiftReport::new(
        epoch(),
        vec![make_abstained_default(WorkloadDimension::ComputeIntensity)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// 21. WindowSummary serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_window_summary_serde_roundtrip() {
    let ws = WindowSummary {
        window_index: 7,
        sample_count: 256,
        mean_millionths: 500_000,
        variance_millionths: 25_000,
        embedding_fingerprint: "abc123deadbeef".to_string(),
    };
    let json = serde_json::to_string(&ws).unwrap();
    let back: WindowSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(ws, back);
}

#[test]
fn enrichment_window_summary_zero_values_serde() {
    let ws = WindowSummary {
        window_index: 0,
        sample_count: 0,
        mean_millionths: 0,
        variance_millionths: 0,
        embedding_fingerprint: String::new(),
    };
    let json = serde_json::to_string(&ws).unwrap();
    let back: WindowSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(ws, back);
}

// ---------------------------------------------------------------------------
// 22. AggregateShiftReport serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_serde_roundtrip_mixed() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 50_000),
        make_abstained_default(WorkloadDimension::AllocationPattern),
        make_measured(WorkloadDimension::ModuleGraphShape, 200_000),
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    let json = serde_json::to_string(&report).unwrap();
    let back: AggregateShiftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_aggregate_serde_roundtrip_empty() {
    let report = AggregateShiftReport::new(epoch(), Vec::new());
    let json = serde_json::to_string(&report).unwrap();
    let back: AggregateShiftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// 23. AggregateShiftReport schema_version set correctly
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_schema_version_set() {
    let report = AggregateShiftReport::new(epoch(), Vec::new());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// 24. AggregateShiftReport recommends_reevaluation follows aggregate verdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_recommends_reevaluation_when_significant() {
    let results = vec![make_measured(WorkloadDimension::ComputeIntensity, 200_000)];
    let report = AggregateShiftReport::new(epoch(), results);
    assert!(report.recommends_reevaluation());
}

#[test]
fn enrichment_aggregate_does_not_recommend_when_marginal_only() {
    let results = vec![make_measured(WorkloadDimension::ComputeIntensity, 75_000)];
    let report = AggregateShiftReport::new(epoch(), results);
    assert!(!report.recommends_reevaluation());
}

// ---------------------------------------------------------------------------
// 25. Multiple significant dimensions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_multiple_significant_dimensions() {
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 200_000),
        make_measured(WorkloadDimension::AllocationPattern, 300_000),
        make_measured(WorkloadDimension::ModuleGraphShape, 500_000),
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.significant_count, 3);
    assert_eq!(report.aggregate_verdict, ShiftVerdict::SignificantShift);
    let shifted = report.significantly_shifted_dimensions();
    assert_eq!(shifted.len(), 3);
}

// ---------------------------------------------------------------------------
// 26. Abstained with measured still yields correct verdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_abstained_does_not_override_no_shift() {
    // One measured NoShift + one abstained -> NoShift (not Inconclusive)
    let results = vec![
        make_measured(WorkloadDimension::ComputeIntensity, 5_000),
        make_abstained_default(WorkloadDimension::AllocationPattern),
    ];
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.aggregate_verdict, ShiftVerdict::NoShift);
}

// ---------------------------------------------------------------------------
// 27. Single abstained is Inconclusive
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_single_abstained_is_inconclusive() {
    let results = vec![make_abstained_default(WorkloadDimension::ComputeIntensity)];
    let report = AggregateShiftReport::new(epoch(), results);
    assert_eq!(report.aggregate_verdict, ShiftVerdict::Inconclusive);
}

// ---------------------------------------------------------------------------
// 28. Epoch preservation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_preserves_epoch() {
    let e = SecurityEpoch::from_raw(999);
    let report = AggregateShiftReport::new(e, Vec::new());
    assert_eq!(report.epoch, e);
}
