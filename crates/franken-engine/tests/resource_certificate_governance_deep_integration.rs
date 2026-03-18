//! Deep integration tests for resource_certificate_governance module.
//!
//! Covers: resource dimension enumeration, certificate evidence creation,
//! utilisation calculations, serde roundtrips, Display impls, and
//! content-hash determinism for evidence entries.

use frankenengine_engine::resource_certificate_governance::{
    BEAD_ID, COMPONENT, CertificateEvidence, DEFAULT_MAX_REGRESSION_MILLIONTHS,
    DEFAULT_MAX_TAIL_RISK_MILLIONTHS, DEFAULT_MAX_UTILISATION_MILLIONTHS, DEFAULT_MIN_SAMPLES,
    FIXED_ONE, POLICY_ID, ResourceDimension, SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn deep_fixed_one_is_million() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn deep_default_thresholds_sane() {
    assert!(DEFAULT_MAX_REGRESSION_MILLIONTHS < FIXED_ONE);
    assert!(DEFAULT_MAX_TAIL_RISK_MILLIONTHS < FIXED_ONE);
    assert!(DEFAULT_MAX_UTILISATION_MILLIONTHS < FIXED_ONE);
    assert!(DEFAULT_MIN_SAMPLES > 0);
}

// ---------------------------------------------------------------------------
// ResourceDimension
// ---------------------------------------------------------------------------

#[test]
fn deep_resource_dimension_all_count() {
    assert_eq!(ResourceDimension::all().len(), 10);
}

#[test]
fn deep_resource_dimension_display_all() {
    let expected = [
        (ResourceDimension::CpuTime, "cpu_time"),
        (ResourceDimension::WallTime, "wall_time"),
        (ResourceDimension::HeapMemory, "heap_memory"),
        (ResourceDimension::StackDepth, "stack_depth"),
        (ResourceDimension::AllocationCount, "allocation_count"),
        (ResourceDimension::IoOperations, "io_operations"),
        (ResourceDimension::NetworkBandwidth, "network_bandwidth"),
        (ResourceDimension::FileDescriptors, "file_descriptors"),
        (ResourceDimension::GcPause, "gc_pause"),
        (ResourceDimension::InstructionCount, "instruction_count"),
    ];
    for (dim, name) in expected {
        assert_eq!(format!("{dim}"), name);
    }
}

#[test]
fn deep_resource_dimension_serde_roundtrip() {
    for dim in ResourceDimension::all() {
        let json = serde_json::to_string(dim).unwrap();
        let decoded: ResourceDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, decoded);
    }
}

#[test]
fn deep_resource_dimension_display_unique() {
    let mut names = std::collections::BTreeSet::new();
    for dim in ResourceDimension::all() {
        assert!(names.insert(format!("{dim}")), "Duplicate: {dim}");
    }
}

// ---------------------------------------------------------------------------
// CertificateEvidence
// ---------------------------------------------------------------------------

#[test]
fn deep_evidence_within_budget() {
    let ev = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "workload-1".to_string(),
        1000, // certified
        500,  // measured (50%)
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert!(ev.within_budget);
    assert_eq!(ev.utilisation_millionths, 500_000); // 50%
}

#[test]
fn deep_evidence_over_budget() {
    let ev = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "workload-2".to_string(),
        1000,
        950, // 95%, above 90% threshold
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert!(!ev.within_budget);
    assert_eq!(ev.utilisation_millionths, 950_000);
}

#[test]
fn deep_evidence_exact_threshold() {
    let ev = CertificateEvidence::new(
        ResourceDimension::HeapMemory,
        "workload-3".to_string(),
        1000,
        900, // 90% = exactly at threshold
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert!(ev.within_budget);
    assert_eq!(ev.utilisation_millionths, 900_000);
}

#[test]
fn deep_evidence_zero_usage() {
    let ev = CertificateEvidence::new(
        ResourceDimension::IoOperations,
        "workload-idle".to_string(),
        1000,
        0,
        30,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert!(ev.within_budget);
    assert_eq!(ev.utilisation_millionths, 0);
}

#[test]
fn deep_evidence_zero_budget_nonzero_usage() {
    // Edge case: certified_budget is 0 but usage is nonzero → should be FIXED_ONE
    let ev = CertificateEvidence::new(
        ResourceDimension::StackDepth,
        "workload-edge".to_string(),
        0,
        100,
        30,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ev.utilisation_millionths, FIXED_ONE);
    assert!(!ev.within_budget);
}

#[test]
fn deep_evidence_zero_budget_zero_usage() {
    let ev = CertificateEvidence::new(
        ResourceDimension::AllocationCount,
        "workload-noop".to_string(),
        0,
        0,
        30,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ev.utilisation_millionths, 0);
    assert!(ev.within_budget);
}

#[test]
fn deep_evidence_hash_deterministic() {
    let ev1 = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "workload-det".to_string(),
        1000,
        500,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let ev2 = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "workload-det".to_string(),
        1000,
        500,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_eq!(ev1.evidence_hash, ev2.evidence_hash);
}

#[test]
fn deep_evidence_hash_changes_on_dimension() {
    let ev1 = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "workload".to_string(),
        1000,
        500,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let ev2 = CertificateEvidence::new(
        ResourceDimension::WallTime,
        "workload".to_string(),
        1000,
        500,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_ne!(ev1.evidence_hash, ev2.evidence_hash);
}

#[test]
fn deep_evidence_hash_changes_on_workload() {
    let ev1 = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "workload-a".to_string(),
        1000,
        500,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let ev2 = CertificateEvidence::new(
        ResourceDimension::CpuTime,
        "workload-b".to_string(),
        1000,
        500,
        100,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    assert_ne!(ev1.evidence_hash, ev2.evidence_hash);
}

#[test]
fn deep_evidence_serde_roundtrip() {
    let ev = CertificateEvidence::new(
        ResourceDimension::GcPause,
        "serde-test".to_string(),
        5000,
        2500,
        50,
        DEFAULT_MAX_UTILISATION_MILLIONTHS,
    );
    let json = serde_json::to_string(&ev).unwrap();
    let decoded: CertificateEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, decoded);
}
