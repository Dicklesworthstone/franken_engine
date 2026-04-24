//! Golden file regression tests for security certificate serialization.
//!
//! Bead: bd-3w282
//!
//! Tests that security certificates serialize to stable JSON output to catch
//! serialization regressions that could break security validation.

use std::fs;
use std::path::Path;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::resource_certificate_governance::{
    BEAD_ID as RCG_BEAD_ID, COMPONENT as RCG_COMPONENT, CertificateEvidence, FIXED_ONE,
    GovernanceReceipt, GovernanceVerdict, RegressionEntry, ResourceDimension,
    SCHEMA_VERSION as RCG_SCHEMA_VERSION, TailRiskEntry,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::timescale_separation_certificate::{
    CERTIFICATE_BUNDLE_SCHEMA_VERSION, CertificateBundle, ControllerPairId,
    ControllerTimescaleProfile, DEFAULT_MARGINAL_RATIO_MILLIONTHS,
    DEFAULT_SUFFICIENT_RATIO_MILLIONTHS, RatioBasis, SeparationVerdict,
    TIMESCALE_CERTIFICATE_BEAD_ID, TIMESCALE_CERTIFICATE_SCHEMA_VERSION, TimescaleRatio,
    TimescaleSeparationCertificate,
};

use std::collections::{BTreeMap, BTreeSet};

/// Test helper: assert golden file matches actual serialization.
fn assert_golden(test_name: &str, actual: &str) {
    let golden_path =
        Path::new("tests/goldens/certificates").join(format!("{}.golden.json", test_name));

    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, actual).unwrap();
        eprintln!("UPDATED golden: {}", golden_path.display());
        return;
    }

    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file not found: {}\n\
             Run with UPDATE_GOLDENS=1 to create it",
            golden_path.display()
        )
    });

    if actual.trim() != expected.trim() {
        let actual_path = golden_path.with_extension("actual.json");
        fs::write(&actual_path, actual).unwrap();
        panic!(
            "GOLDEN MISMATCH: {}\n\
             Expected: {}\n\
             Actual:   {}\n\
             Run: diff {} {}",
            test_name,
            golden_path.display(),
            actual_path.display(),
            golden_path.display(),
            actual_path.display(),
        );
    }
}

/// Create deterministic JSON from serde-serializable type.
fn to_deterministic_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("serialization should succeed")
}

#[test]
fn certificate_evidence_basic() {
    let evidence = CertificateEvidence {
        dimension: ResourceDimension::CpuTime,
        workload_id: "test_workload_1".to_string(),
        certified_budget: 5_000_000,     // 5 seconds in microseconds
        measured_usage: 3_200_000,       // 3.2 seconds in microseconds
        utilisation_millionths: 640_000, // 64% utilization
        within_budget: true,
        sample_count: 1000,
        evidence_hash: ContentHash::compute(b"test_evidence_1"),
    };

    let json = to_deterministic_json(&evidence);
    assert_golden("certificate_evidence_basic", &json);
}

#[test]
fn certificate_evidence_memory() {
    let evidence = CertificateEvidence {
        dimension: ResourceDimension::HeapMemory,
        workload_id: "memory_intensive_workload".to_string(),
        certified_budget: 1_000_000_000, // 1GB in bytes
        measured_usage: 850_000_000,     // 850MB actual usage
        utilisation_millionths: 850_000, // 85% utilization
        within_budget: true,
        sample_count: 500,
        evidence_hash: ContentHash::compute(b"memory_test_hash"),
    };

    let json = to_deterministic_json(&evidence);
    assert_golden("certificate_evidence_memory", &json);
}

#[test]
fn certificate_evidence_network_io() {
    let evidence = CertificateEvidence {
        dimension: ResourceDimension::NetworkBandwidth,
        workload_id: "network_heavy_service".to_string(),
        certified_budget: 100_000_000,   // 100MB bandwidth budget
        measured_usage: 42_000_000,      // 42MB actual usage
        utilisation_millionths: 420_000, // 42% utilization
        within_budget: true,
        sample_count: 750,
        evidence_hash: ContentHash::compute(b"network_io_evidence"),
    };

    let json = to_deterministic_json(&evidence);
    assert_golden("certificate_evidence_network_io", &json);
}

#[test]
fn timescale_separation_certificate_sufficient() {
    let cert = TimescaleSeparationCertificate {
        schema_version: TIMESCALE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        certificate_id: "cert_sufficient_001".to_string(),
        pair: ControllerPairId {
            fast_controller: "gc_controller".to_string(),
            slow_controller: "batch_processor".to_string(),
        },
        ratio: TimescaleRatio {
            pair: ControllerPairId {
                fast_controller: "gc_controller".to_string(),
                slow_controller: "batch_processor".to_string(),
            },
            ratio_millionths: 50_000_000, // 50x ratio
            ratio_basis: RatioBasis::Observation,
        },
        verdict: SeparationVerdict::Sufficient,
        sufficient_threshold_millionths: DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
        marginal_threshold_millionths: DEFAULT_MARGINAL_RATIO_MILLIONTHS,
        fast_profile: ControllerTimescaleProfile {
            controller_id: "gc_controller".to_string(),
            observation_interval_millionths: 100_000_000, // 100ms in millionths of second
            write_interval_millionths: 100_000_000,
            sample_count: 1000,
            measured_epoch: 1640995200,
        },
        slow_profile: ControllerTimescaleProfile {
            controller_id: "batch_processor".to_string(),
            observation_interval_millionths: 5_000_000_000, // 5 seconds in millionths of second
            write_interval_millionths: 5_000_000_000,
            sample_count: 200,
            measured_epoch: 1640995200,
        },
        issued_epoch: 1640995200, // Fixed timestamp for determinism
        evidence_ids: vec!["evidence_001".to_string(), "evidence_002".to_string()],
    };

    let json = to_deterministic_json(&cert);
    assert_golden("timescale_certificate_sufficient", &json);
}

#[test]
fn timescale_separation_certificate_marginal() {
    let cert = TimescaleSeparationCertificate {
        schema_version: TIMESCALE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        certificate_id: "cert_marginal_002".to_string(),
        pair: ControllerPairId {
            fast_controller: "realtime_monitor".to_string(),
            slow_controller: "periodic_cleanup".to_string(),
        },
        ratio: TimescaleRatio {
            fast_interval_micros: 50_000,  // 50ms
            slow_interval_micros: 200_000, // 200ms
            ratio_millionths: 4_000_000,   // 4x ratio (between marginal and sufficient)
        },
        verdict: SeparationVerdict::Marginal,
        sufficient_threshold_millionths: DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
        marginal_threshold_millionths: DEFAULT_MARGINAL_RATIO_MILLIONTHS,
        computed_epoch: 1640995300,
    };

    let json = to_deterministic_json(&cert);
    assert_golden("timescale_certificate_marginal", &json);
}

#[test]
fn timescale_separation_certificate_insufficient() {
    let cert = TimescaleSeparationCertificate {
        schema_version: TIMESCALE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        certificate_id: "cert_insufficient_003".to_string(),
        pair: ControllerPairId {
            fast_controller: "high_freq_trader".to_string(),
            slow_controller: "low_freq_trader".to_string(),
        },
        ratio: TimescaleRatio {
            fast_interval_micros: 1_000, // 1ms
            slow_interval_micros: 2_000, // 2ms
            ratio_millionths: 2_000_000, // 2x ratio (below marginal threshold)
        },
        verdict: SeparationVerdict::Insufficient,
        sufficient_threshold_millionths: DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
        marginal_threshold_millionths: DEFAULT_MARGINAL_RATIO_MILLIONTHS,
        computed_epoch: 1640995400,
    };

    let json = to_deterministic_json(&cert);
    assert_golden("timescale_certificate_insufficient", &json);
}

#[test]
fn certificate_bundle_mixed_verdicts() {
    let certificates = vec![
        TimescaleSeparationCertificate {
            schema_version: TIMESCALE_CERTIFICATE_SCHEMA_VERSION.to_string(),
            bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
            certificate_id: "bundle_cert_1".to_string(),
            pair: ControllerPairId {
                fast_controller: "controller_a".to_string(),
                slow_controller: "controller_b".to_string(),
            },
            ratio: TimescaleRatio {
                fast_interval_micros: 10_000,
                slow_interval_micros: 100_000,
                ratio_millionths: 10_000_000, // 10x - sufficient
            },
            verdict: SeparationVerdict::Sufficient,
            sufficient_threshold_millionths: DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
            marginal_threshold_millionths: DEFAULT_MARGINAL_RATIO_MILLIONTHS,
            computed_epoch: 1640995500,
        },
        TimescaleSeparationCertificate {
            schema_version: TIMESCALE_CERTIFICATE_SCHEMA_VERSION.to_string(),
            bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
            certificate_id: "bundle_cert_2".to_string(),
            pair: ControllerPairId {
                fast_controller: "controller_a".to_string(),
                slow_controller: "controller_c".to_string(),
            },
            ratio: TimescaleRatio {
                fast_interval_micros: 10_000,
                slow_interval_micros: 30_000,
                ratio_millionths: 3_000_000, // 3x - marginal
            },
            verdict: SeparationVerdict::Marginal,
            sufficient_threshold_millionths: DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
            marginal_threshold_millionths: DEFAULT_MARGINAL_RATIO_MILLIONTHS,
            computed_epoch: 1640995500,
        },
    ];

    let bundle = CertificateBundle {
        schema_version: CERTIFICATE_BUNDLE_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        certificates,
        overall_verdict: SeparationVerdict::Marginal, // Worst case
        bundle_epoch: 1640995500,
        pair_count: 2,
        sufficient_count: 1,
        marginal_count: 1,
        insufficient_count: 0,
    };

    let json = to_deterministic_json(&bundle);
    assert_golden("certificate_bundle_mixed_verdicts", &json);
}

#[test]
fn governance_receipt_comprehensive() {
    let mut dimensions_evaluated = BTreeSet::new();
    dimensions_evaluated.insert(ResourceDimension::CpuTime);
    dimensions_evaluated.insert(ResourceDimension::Memory);
    dimensions_evaluated.insert(ResourceDimension::NetworkIo);

    let mut dimensions_missing = BTreeSet::new();
    dimensions_missing.insert(ResourceDimension::DiskIo);

    let certificates = vec![
        CertificateEvidence {
            dimension: ResourceDimension::CpuTime,
            workload_id: "web_server".to_string(),
            certified_budget: 2_000_000,
            measured_usage: 1_500_000,
            utilisation_millionths: 750_000, // 75%
            content_hash: ContentHash::compute(b"cpu_evidence"),
        },
        CertificateEvidence {
            dimension: ResourceDimension::Memory,
            workload_id: "web_server".to_string(),
            certified_budget: 500_000_000,   // 500MB
            measured_usage: 320_000_000,     // 320MB
            utilisation_millionths: 640_000, // 64%
            content_hash: ContentHash::compute(b"memory_evidence"),
        },
    ];

    let regressions = vec![RegressionEntry {
        dimension: ResourceDimension::CpuTime,
        workload_id: "web_server".to_string(),
        previous_usage: 1_400_000,
        current_usage: 1_500_000,
        regression_millionths: 71_429, // ~7.14% regression
        baseline_hash: ContentHash::compute(b"cpu_baseline"),
        current_hash: ContentHash::compute(b"cpu_current"),
    }];

    let tail_risks = vec![TailRiskEntry {
        dimension: ResourceDimension::Memory,
        workload_id: "web_server".to_string(),
        tail_ratio_millionths: 2_500_000,     // p99/p50 = 2.5x
        baseline_ratio_millionths: 2_000_000, // baseline = 2.0x
        drift_millionths: 250_000,            // 25% worse tail behavior
        baseline_hash: ContentHash::compute(b"tail_baseline"),
        current_hash: ContentHash::compute(b"tail_current"),
    }];

    let receipt = GovernanceReceipt {
        verdict: GovernanceVerdict::Approved,
        epoch: SecurityEpoch::from_raw(42),
        dimensions_evaluated,
        dimensions_missing,
        certificates,
        regressions,
        tail_risks,
        publication_gate: true,
        regression_gate: true,
        tail_risk_gate: true,
        policy_snapshot: PublicationPolicy {
            max_regression_millionths: 100_000, // 10% max regression
            max_tail_drift_millionths: 500_000, // 50% max tail drift
            require_all_dimensions: false,
            budget_threshold_millionths: 900_000, // 90% utilization threshold
        },
        receipt_hash: ContentHash::compute(b"governance_receipt_hash"),
    };

    let json = to_deterministic_json(&receipt);
    assert_golden("governance_receipt_comprehensive", &json);
}

#[test]
fn governance_receipt_denial() {
    let mut dimensions_evaluated = BTreeSet::new();
    dimensions_evaluated.insert(ResourceDimension::CpuTime);

    let certificates = vec![CertificateEvidence {
        dimension: ResourceDimension::CpuTime,
        workload_id: "overloaded_service".to_string(),
        certified_budget: 1_000_000,
        measured_usage: 1_200_000,         // Over budget!
        utilisation_millionths: 1_200_000, // 120% utilization
        content_hash: ContentHash::compute(b"overloaded_evidence"),
    }];

    let regressions = vec![RegressionEntry {
        dimension: ResourceDimension::CpuTime,
        workload_id: "overloaded_service".to_string(),
        previous_usage: 800_000,
        current_usage: 1_200_000,
        regression_millionths: 500_000, // 50% regression - way over limit!
        baseline_hash: ContentHash::compute(b"regression_baseline"),
        current_hash: ContentHash::compute(b"regression_current"),
    }];

    let receipt = GovernanceReceipt {
        verdict: GovernanceVerdict::Denied,
        epoch: SecurityEpoch::from_raw(43),
        dimensions_evaluated,
        dimensions_missing: BTreeSet::new(),
        certificates,
        regressions,
        tail_risks: Vec::new(),
        publication_gate: false, // Failed due to over-budget
        regression_gate: false,  // Failed due to high regression
        tail_risk_gate: true,    // No tail risk data
        policy_snapshot: PublicationPolicy {
            max_regression_millionths: 100_000, // 10% max regression
            max_tail_drift_millionths: 500_000,
            require_all_dimensions: false,
            budget_threshold_millionths: 1_000_000, // 100% utilization threshold
        },
        receipt_hash: ContentHash::compute(b"denial_receipt_hash"),
    };

    let json = to_deterministic_json(&receipt);
    assert_golden("governance_receipt_denial", &json);
}

// Test that UPDATE_GOLDENS workflow works
#[test]
fn golden_file_update_workflow() {
    // Simple test case for workflow verification
    let simple_evidence = CertificateEvidence {
        dimension: ResourceDimension::IoOperations,
        workload_id: "simple_test".to_string(),
        certified_budget: 1000,
        measured_usage: 500,
        utilisation_millionths: 500_000, // 50%
        within_budget: true,
        sample_count: 100,
        evidence_hash: ContentHash::compute(b"workflow_test"),
    };

    let json = to_deterministic_json(&simple_evidence);
    assert_golden("golden_workflow_test", &json);
}
