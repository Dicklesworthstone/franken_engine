//! Integration tests for `kernel_shift_monitor` module.
//!
//! Validates public API, serde contracts, determinism, shift detection,
//! abstention semantics, and aggregate reporting.

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

use frankenengine_engine::kernel_shift_monitor::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(300)
}

fn config(dim: WorkloadDimension) -> MonitorConfig {
    MonitorConfig::default_for(dim)
}

fn measured(dim: WorkloadDimension, mmd: u64) -> MonitorResult {
    MonitorResult::Measured(MmdResult::compute(dim, mmd, &config(dim), 256, 256))
}

fn abstained(dim: WorkloadDimension) -> MonitorResult {
    MonitorResult::Abstained {
        dimension: dim,
        reason: MonitorAbstention::UncalibratedBandwidth,
    }
}

fn report(results: Vec<MonitorResult>) -> AggregateShiftReport {
    AggregateShiftReport::new(epoch(), results)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "kernel_shift_monitor");
}

#[test]
fn window_size_constraints() {
    const { assert!(DEFAULT_WINDOW_SIZE >= MIN_WINDOW_SIZE) };
    const { assert!(MIN_WINDOW_SIZE > 0) };
}

#[test]
fn threshold_constraints() {
    const { assert!(DEFAULT_MMD_THRESHOLD > 0) };
    const { assert!(DEFAULT_MMD_THRESHOLD <= 1_000_000) };
    const { assert!(DEFAULT_FALSE_ALARM_BUDGET > 0) };
}

// ---------------------------------------------------------------------------
// WorkloadDimension
// ---------------------------------------------------------------------------

#[test]
fn dimension_all_length() {
    assert_eq!(WorkloadDimension::ALL.len(), 8);
}

#[test]
fn dimension_names_unique() {
    let names: BTreeSet<&str> = WorkloadDimension::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(names.len(), WorkloadDimension::ALL.len());
}

#[test]
fn dimension_display_matches_as_str() {
    for d in WorkloadDimension::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn dimension_serde_all() {
    for d in WorkloadDimension::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: WorkloadDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ---------------------------------------------------------------------------
// KernelKind
// ---------------------------------------------------------------------------

#[test]
fn kernel_all_length() {
    assert_eq!(KernelKind::ALL.len(), 4);
}

#[test]
fn kernel_names_unique() {
    let names: BTreeSet<&str> = KernelKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), KernelKind::ALL.len());
}

#[test]
fn kernel_bandwidth_requirements() {
    assert!(KernelKind::Gaussian.requires_bandwidth());
    assert!(KernelKind::Laplacian.requires_bandwidth());
    assert!(!KernelKind::Linear.requires_bandwidth());
    assert!(!KernelKind::Polynomial.requires_bandwidth());
}

#[test]
fn kernel_serde_all() {
    for k in KernelKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: KernelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// MonitorAbstention
// ---------------------------------------------------------------------------

#[test]
fn abstention_tags_unique() {
    let reasons = vec![
        MonitorAbstention::InsufficientSamples {
            available: 10,
            required: 32,
        },
        MonitorAbstention::UncalibratedBandwidth,
        MonitorAbstention::EmptyReferenceDistribution,
        MonitorAbstention::IncompleteWindow {
            filled: 20,
            window_size: 256,
        },
        MonitorAbstention::DisabledByPolicy,
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 5);
}

#[test]
fn abstention_serde_roundtrip() {
    let a = MonitorAbstention::IncompleteWindow {
        filled: 50,
        window_size: 256,
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: MonitorAbstention = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn abstention_display_content() {
    let a = MonitorAbstention::InsufficientSamples {
        available: 5,
        required: 32,
    };
    let s = a.to_string();
    assert!(s.contains("5"));
    assert!(s.contains("32"));
}

// ---------------------------------------------------------------------------
// ShiftVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_all_length() {
    assert_eq!(ShiftVerdict::ALL.len(), 4);
}

#[test]
fn verdict_reevaluation_semantics() {
    assert!(!ShiftVerdict::NoShift.recommends_reevaluation());
    assert!(!ShiftVerdict::MarginalShift.recommends_reevaluation());
    assert!(ShiftVerdict::SignificantShift.recommends_reevaluation());
    assert!(!ShiftVerdict::Inconclusive.recommends_reevaluation());
}

#[test]
fn verdict_concerning_semantics() {
    assert!(!ShiftVerdict::NoShift.is_concerning());
    assert!(ShiftVerdict::MarginalShift.is_concerning());
    assert!(ShiftVerdict::SignificantShift.is_concerning());
    assert!(!ShiftVerdict::Inconclusive.is_concerning());
}

#[test]
fn verdict_serde_all() {
    for v in ShiftVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// MonitorConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_valid() {
    let c = MonitorConfig::default_for(WorkloadDimension::ComputeIntensity);
    assert_eq!(c.dimension, WorkloadDimension::ComputeIntensity);
    assert_eq!(c.kernel, KernelKind::Gaussian);
    assert_eq!(c.window_size, DEFAULT_WINDOW_SIZE);
    assert!(c.marginal_threshold_millionths < c.mmd_threshold_millionths);
}

#[test]
fn config_serde_roundtrip() {
    let c = MonitorConfig::default_for(WorkloadDimension::GcPressureProfile);
    let json = serde_json::to_string(&c).unwrap();
    let back: MonitorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// MmdResult
// ---------------------------------------------------------------------------

#[test]
fn mmd_no_shift() {
    let c = config(WorkloadDimension::ComputeIntensity);
    let r = MmdResult::compute(WorkloadDimension::ComputeIntensity, 10_000, &c, 256, 256);
    assert_eq!(r.verdict, ShiftVerdict::NoShift);
    assert!(!r.is_significant());
    assert!(!r.is_marginal());
}

#[test]
fn mmd_marginal() {
    let c = config(WorkloadDimension::ComputeIntensity);
    let r = MmdResult::compute(WorkloadDimension::ComputeIntensity, 60_000, &c, 256, 256);
    assert_eq!(r.verdict, ShiftVerdict::MarginalShift);
    assert!(!r.is_significant());
    assert!(r.is_marginal());
}

#[test]
fn mmd_significant() {
    let c = config(WorkloadDimension::ComputeIntensity);
    let r = MmdResult::compute(WorkloadDimension::ComputeIntensity, 200_000, &c, 256, 256);
    assert_eq!(r.verdict, ShiftVerdict::SignificantShift);
    assert!(r.is_significant());
}

#[test]
fn mmd_at_threshold_boundary() {
    let c = config(WorkloadDimension::ComputeIntensity);
    let r = MmdResult::compute(
        WorkloadDimension::ComputeIntensity,
        DEFAULT_MMD_THRESHOLD,
        &c,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::SignificantShift);
}

#[test]
fn mmd_just_below_threshold() {
    let c = config(WorkloadDimension::ComputeIntensity);
    let r = MmdResult::compute(
        WorkloadDimension::ComputeIntensity,
        DEFAULT_MMD_THRESHOLD - 1,
        &c,
        256,
        256,
    );
    assert_eq!(r.verdict, ShiftVerdict::MarginalShift);
}

#[test]
fn mmd_serde_roundtrip() {
    let c = config(WorkloadDimension::AllocationPattern);
    let r = MmdResult::compute(WorkloadDimension::AllocationPattern, 75_000, &c, 100, 200);
    let json = serde_json::to_string(&r).unwrap();
    let back: MmdResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// MonitorResult
// ---------------------------------------------------------------------------

#[test]
fn result_measured_properties() {
    let r = measured(WorkloadDimension::ComputeIntensity, 5_000);
    assert!(r.is_measured());
    assert!(!r.is_abstained());
    assert_eq!(r.dimension(), WorkloadDimension::ComputeIntensity);
    assert!(r.verdict().is_some());
    assert!(r.mmd_millionths().is_some());
}

#[test]
fn result_abstained_properties() {
    let r = abstained(WorkloadDimension::GcPressureProfile);
    assert!(r.is_abstained());
    assert!(!r.is_measured());
    assert_eq!(r.dimension(), WorkloadDimension::GcPressureProfile);
    assert!(r.verdict().is_none());
    assert!(r.mmd_millionths().is_none());
}

#[test]
fn result_serde_measured_roundtrip() {
    let r = measured(WorkloadDimension::HostcallProfile, 80_000);
    let json = serde_json::to_string(&r).unwrap();
    let back: MonitorResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn result_serde_abstained_roundtrip() {
    let r = abstained(WorkloadDimension::IoSchedulingPattern);
    let json = serde_json::to_string(&r).unwrap();
    let back: MonitorResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// AggregateShiftReport
// ---------------------------------------------------------------------------

#[test]
fn report_empty() {
    let r = report(Vec::new());
    assert_eq!(r.monitor_count(), 0);
    assert_eq!(r.measured_count(), 0);
    assert_eq!(r.aggregate_verdict, ShiftVerdict::NoShift);
    assert_eq!(r.coverage_millionths(), 0);
    assert!(!r.recommends_reevaluation());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_all_no_shift() {
    let results: Vec<_> = WorkloadDimension::ALL
        .iter()
        .map(|d| measured(*d, 5_000))
        .collect();
    let r = report(results);
    assert_eq!(r.aggregate_verdict, ShiftVerdict::NoShift);
    assert_eq!(r.significant_count, 0);
    assert_eq!(r.marginal_count, 0);
    assert_eq!(r.abstained_count, 0);
    assert_eq!(r.coverage_millionths(), 1_000_000);
}

#[test]
fn report_significant_shift_propagates() {
    let results = vec![
        measured(WorkloadDimension::ComputeIntensity, 5_000),
        measured(WorkloadDimension::AllocationPattern, 200_000),
    ];
    let r = report(results);
    assert_eq!(r.aggregate_verdict, ShiftVerdict::SignificantShift);
    assert_eq!(r.significant_count, 1);
    assert!(r.recommends_reevaluation());
}

#[test]
fn report_marginal_shift_only() {
    let results = vec![
        measured(WorkloadDimension::ComputeIntensity, 5_000),
        measured(WorkloadDimension::AllocationPattern, 60_000),
    ];
    let r = report(results);
    assert_eq!(r.aggregate_verdict, ShiftVerdict::MarginalShift);
    assert_eq!(r.marginal_count, 1);
    assert!(!r.recommends_reevaluation());
}

#[test]
fn report_all_abstained() {
    let results: Vec<_> = WorkloadDimension::ALL
        .iter()
        .map(|d| abstained(*d))
        .collect();
    let r = report(results);
    assert_eq!(r.aggregate_verdict, ShiftVerdict::Inconclusive);
    assert_eq!(r.abstained_count, WorkloadDimension::ALL.len());
    assert_eq!(r.coverage_millionths(), 0);
}

#[test]
fn report_mixed_measured_and_abstained() {
    let results = vec![
        measured(WorkloadDimension::ComputeIntensity, 5_000),
        abstained(WorkloadDimension::AllocationPattern),
        measured(WorkloadDimension::ModuleGraphShape, 200_000),
    ];
    let r = report(results);
    assert_eq!(r.aggregate_verdict, ShiftVerdict::SignificantShift);
    assert_eq!(r.measured_count(), 2);
    assert_eq!(r.abstained_count, 1);
}

#[test]
fn report_significantly_shifted_dimensions() {
    let results = vec![
        measured(WorkloadDimension::ComputeIntensity, 200_000),
        measured(WorkloadDimension::AllocationPattern, 5_000),
        measured(WorkloadDimension::ModuleGraphShape, 150_000),
    ];
    let r = report(results);
    let shifted = r.significantly_shifted_dimensions();
    assert_eq!(shifted.len(), 2);
    assert!(shifted.contains(&WorkloadDimension::ComputeIntensity));
    assert!(shifted.contains(&WorkloadDimension::ModuleGraphShape));
}

#[test]
fn report_result_for_lookup() {
    let results = vec![
        measured(WorkloadDimension::ComputeIntensity, 30_000),
        abstained(WorkloadDimension::GcPressureProfile),
    ];
    let r = report(results);
    assert!(r.result_for(WorkloadDimension::ComputeIntensity).is_some());
    assert!(r.result_for(WorkloadDimension::GcPressureProfile).is_some());
    assert!(
        r.result_for(WorkloadDimension::IoSchedulingPattern)
            .is_none()
    );
}

#[test]
fn report_content_hash_deterministic() {
    let r1 = report(vec![measured(WorkloadDimension::ComputeIntensity, 50_000)]);
    let r2 = report(vec![measured(WorkloadDimension::ComputeIntensity, 50_000)]);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_different_results_different_hash() {
    let r1 = report(vec![measured(WorkloadDimension::ComputeIntensity, 50_000)]);
    let r2 = report(vec![measured(WorkloadDimension::ComputeIntensity, 100_000)]);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let results = vec![
        measured(WorkloadDimension::ComputeIntensity, 50_000),
        abstained(WorkloadDimension::AllocationPattern),
    ];
    let r = report(results);
    let json = serde_json::to_string(&r).unwrap();
    let back: AggregateShiftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}
