//! Deep integration tests for kernel_shift_monitor module.
//!
//! Covers: workload dimension enumeration, kernel kind properties,
//! monitor abstention classification, serde roundtrips, Display impls,
//! and constant validation.

use frankenengine_engine::kernel_shift_monitor::{
    BEAD_ID, COMPONENT, DEFAULT_FALSE_ALARM_BUDGET, DEFAULT_MMD_THRESHOLD, DEFAULT_WINDOW_SIZE,
    KernelKind, MAX_MONITORS, MIN_WINDOW_SIZE, MonitorAbstention, SCHEMA_VERSION,
    WorkloadDimension,
};

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
