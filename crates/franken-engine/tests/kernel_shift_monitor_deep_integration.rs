//! Deep integration tests for kernel_shift_monitor module.
//!
//! Covers: workload dimension enumeration, kernel kind properties,
//! monitor abstention classification, serde roundtrips, Display impls,
//! and constant validation.

use frankenengine_engine::kernel_shift_monitor::{
    AggregateShiftReport, BEAD_ID, COMPONENT, DEFAULT_FALSE_ALARM_BUDGET, DEFAULT_MMD_THRESHOLD,
    DEFAULT_WINDOW_SIZE, KernelKind, MAX_MONITORS, MIN_WINDOW_SIZE, MonitorAbstention,
    MonitorConfig, MonitorResult, SCHEMA_VERSION, ShiftVerdict, WorkloadDimension,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn deep_window_size_bounds() {
    assert!(DEFAULT_WINDOW_SIZE >= MIN_WINDOW_SIZE);
    assert!(MIN_WINDOW_SIZE > 0);
}

#[test]
fn deep_thresholds_valid() {
    assert!(DEFAULT_MMD_THRESHOLD > 0);
    assert!(DEFAULT_MMD_THRESHOLD <= 1_000_000);
    assert!(DEFAULT_FALSE_ALARM_BUDGET > 0);
    assert!(DEFAULT_FALSE_ALARM_BUDGET <= 1_000_000);
    assert!(MAX_MONITORS > 0);
}

// ---------------------------------------------------------------------------
// WorkloadDimension
// ---------------------------------------------------------------------------

#[test]
fn deep_dimension_all_count() {
    assert_eq!(WorkloadDimension::ALL.len(), 8);
}

#[test]
fn deep_dimension_as_str_nonempty() {
    for dim in WorkloadDimension::ALL {
        assert!(!dim.as_str().is_empty());
        assert!(!dim.as_str().contains(' '));
    }
}

#[test]
fn deep_dimension_display_matches_as_str() {
    for dim in WorkloadDimension::ALL {
        assert_eq!(format!("{dim}"), dim.as_str());
    }
}

#[test]
fn deep_dimension_as_str_unique() {
    let mut names = std::collections::BTreeSet::new();
    for dim in WorkloadDimension::ALL {
        assert!(names.insert(dim.as_str()), "Duplicate: {}", dim.as_str());
    }
}

#[test]
fn deep_dimension_serde_roundtrip() {
    for dim in WorkloadDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let decoded: WorkloadDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, decoded);
    }
}

// ---------------------------------------------------------------------------
// KernelKind
// ---------------------------------------------------------------------------

#[test]
fn deep_kernel_all_count() {
    assert_eq!(KernelKind::ALL.len(), 4);
}

#[test]
fn deep_kernel_as_str_all() {
    let expected = [
        (KernelKind::Gaussian, "gaussian"),
        (KernelKind::Laplacian, "laplacian"),
        (KernelKind::Linear, "linear"),
        (KernelKind::Polynomial, "polynomial"),
    ];
    for (kind, name) in expected {
        assert_eq!(kind.as_str(), name);
        assert_eq!(format!("{kind}"), name);
    }
}

#[test]
fn deep_kernel_requires_bandwidth() {
    assert!(KernelKind::Gaussian.requires_bandwidth());
    assert!(KernelKind::Laplacian.requires_bandwidth());
    assert!(!KernelKind::Linear.requires_bandwidth());
    assert!(!KernelKind::Polynomial.requires_bandwidth());
}

#[test]
fn deep_kernel_serde_roundtrip() {
    for kind in KernelKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let decoded: KernelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// MonitorAbstention
// ---------------------------------------------------------------------------

#[test]
fn deep_abstention_serde_roundtrip() {
    let abstentions = [
        MonitorAbstention::InsufficientSamples {
            available: 10,
            required: 32,
        },
        MonitorAbstention::UncalibratedBandwidth,
        MonitorAbstention::EmptyReferenceDistribution,
        MonitorAbstention::IncompleteWindow {
            filled: 100,
            window_size: 256,
        },
        MonitorAbstention::DisabledByPolicy,
    ];
    for abstention in &abstentions {
        let json = serde_json::to_string(abstention).unwrap();
        let decoded: MonitorAbstention = serde_json::from_str(&json).unwrap();
        assert_eq!(*abstention, decoded);
    }
}

// ---------------------------------------------------------------------------
// Kernel as_str uniqueness
// ---------------------------------------------------------------------------

#[test]
fn deep_kernel_as_str_unique() {
    let mut names = std::collections::BTreeSet::new();
    for kind in KernelKind::ALL {
        assert!(names.insert(kind.as_str()), "Duplicate: {}", kind.as_str());
    }
}

// ---------------------------------------------------------------------------
// Enrichment: ShiftVerdict
// ---------------------------------------------------------------------------

#[test]
fn deep_shift_verdict_all_count() {
    assert_eq!(ShiftVerdict::ALL.len(), 4);
}

#[test]
fn deep_shift_verdict_as_str_unique() {
    let mut names = std::collections::BTreeSet::new();
    for verdict in ShiftVerdict::ALL {
        assert!(
            names.insert(verdict.as_str()),
            "Duplicate: {}",
            verdict.as_str()
        );
    }
}

#[test]
fn deep_shift_verdict_recommends_reevaluation() {
    // Marginal and Significant should recommend reevaluation
    assert!(ShiftVerdict::SignificantShift.recommends_reevaluation());
    assert!(!ShiftVerdict::NoShift.recommends_reevaluation());
}

#[test]
fn deep_shift_verdict_is_concerning() {
    assert!(ShiftVerdict::SignificantShift.is_concerning());
    assert!(!ShiftVerdict::NoShift.is_concerning());
}

#[test]
fn deep_shift_verdict_serde_roundtrip() {
    for verdict in ShiftVerdict::ALL {
        let json = serde_json::to_string(verdict).unwrap();
        let decoded: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*verdict, decoded);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: MonitorConfig
// ---------------------------------------------------------------------------

#[test]
fn deep_monitor_config_default_for_dimension() {
    for dim in WorkloadDimension::ALL {
        let config = MonitorConfig::default_for(*dim);
        assert_eq!(config.dimension, *dim);
        assert!(config.window_size >= MIN_WINDOW_SIZE);
        assert!(config.mmd_threshold_millionths > 0);
    }
}

#[test]
fn deep_monitor_config_serde_roundtrip() {
    let config = MonitorConfig::default_for(WorkloadDimension::IoSchedulingPattern);
    let json = serde_json::to_string(&config).unwrap();
    let decoded: MonitorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: MonitorResult
// ---------------------------------------------------------------------------

#[test]
fn deep_monitor_result_abstained_accessors() {
    let result = MonitorResult::Abstained {
        dimension: WorkloadDimension::ComputeIntensity,
        reason: MonitorAbstention::InsufficientSamples {
            available: 5,
            required: 32,
        },
    };
    assert_eq!(result.dimension(), WorkloadDimension::ComputeIntensity);
    assert!(!result.is_measured());
    assert!(result.is_abstained());
    assert!(result.verdict().is_none());
    assert!(result.mmd_millionths().is_none());
}

#[test]
fn deep_monitor_result_serde_roundtrip() {
    let result = MonitorResult::Abstained {
        dimension: WorkloadDimension::AllocationPattern,
        reason: MonitorAbstention::DisabledByPolicy,
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: MonitorResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: MonitorAbstention tag
// ---------------------------------------------------------------------------

#[test]
fn deep_abstention_tag_nonempty() {
    let abstentions = [
        MonitorAbstention::InsufficientSamples {
            available: 0,
            required: 1,
        },
        MonitorAbstention::UncalibratedBandwidth,
        MonitorAbstention::EmptyReferenceDistribution,
        MonitorAbstention::IncompleteWindow {
            filled: 0,
            window_size: 1,
        },
        MonitorAbstention::DisabledByPolicy,
    ];
    for ab in &abstentions {
        assert!(!ab.tag().is_empty());
    }
}

#[test]
fn deep_abstention_tag_unique() {
    let tags: std::collections::BTreeSet<_> = [
        MonitorAbstention::InsufficientSamples {
            available: 0,
            required: 1,
        },
        MonitorAbstention::UncalibratedBandwidth,
        MonitorAbstention::EmptyReferenceDistribution,
        MonitorAbstention::IncompleteWindow {
            filled: 0,
            window_size: 1,
        },
        MonitorAbstention::DisabledByPolicy,
    ]
    .iter()
    .map(|a| a.tag())
    .collect();
    assert_eq!(tags.len(), 5);
}

// ---------------------------------------------------------------------------
// Enrichment: AggregateShiftReport
// ---------------------------------------------------------------------------

#[test]
fn deep_aggregate_report_empty() {
    let report = AggregateShiftReport::new(SecurityEpoch::from_raw(1), vec![]);
    assert_eq!(report.monitor_count(), 0);
    assert_eq!(report.measured_count(), 0);
}

#[test]
fn deep_aggregate_report_with_abstentions() {
    let results = vec![
        MonitorResult::Abstained {
            dimension: WorkloadDimension::ComputeIntensity,
            reason: MonitorAbstention::DisabledByPolicy,
        },
        MonitorResult::Abstained {
            dimension: WorkloadDimension::AllocationPattern,
            reason: MonitorAbstention::UncalibratedBandwidth,
        },
    ];
    let report = AggregateShiftReport::new(SecurityEpoch::from_raw(2), results);
    assert_eq!(report.monitor_count(), 2);
    assert_eq!(report.measured_count(), 0);
    assert_eq!(report.coverage_millionths(), 0);
}

#[test]
fn deep_aggregate_report_serde_roundtrip() {
    let results = vec![MonitorResult::Abstained {
        dimension: WorkloadDimension::HostcallProfile,
        reason: MonitorAbstention::EmptyReferenceDistribution,
    }];
    let report = AggregateShiftReport::new(SecurityEpoch::from_raw(5), results);
    let json = serde_json::to_string(&report).unwrap();
    let decoded: AggregateShiftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, decoded);
}
