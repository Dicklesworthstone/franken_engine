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
    CertificateEvidence, CertificateGovernanceEvidenceKind, GovernanceEvaluator, GovernanceVerdict,
    PublicationPolicy, ResourceDimension,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::timescale_separation_certificate::{
    CERTIFICATE_BUNDLE_SCHEMA_VERSION, CertificateBundle, ControllerPairId,
    ControllerTimescaleProfile, DEFAULT_MARGINAL_RATIO_MILLIONTHS,
    DEFAULT_SUFFICIENT_RATIO_MILLIONTHS, RatioBasis, SeparationVerdict,
    TIMESCALE_CERTIFICATE_BEAD_ID, TIMESCALE_CERTIFICATE_SCHEMA_VERSION, TimescaleRatio,
    TimescaleSeparationCertificate,
};

use std::collections::BTreeSet;

/// Test helper: assert golden file matches actual serialization.
fn assert_golden(test_name: &str, actual: &str) {
    let golden_path =
        Path::new("tests/golden/certificates").join(format!("{}.golden.json", test_name));

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
            "GOLDEN MISMATCH: {}\n{}\n\
             Expected: {}\n\
             Actual:   {}\n\
             Run: diff {} {}",
            test_name,
            summarize_golden_diff(actual.trim(), expected.trim()),
            golden_path.display(),
            actual_path.display(),
            golden_path.display(),
            actual_path.display(),
        );
    }

    // Sweep any stale .actual.json sibling left by a prior failing run (bd-ub6x8.7).
    let _ = fs::remove_file(golden_path.with_extension("actual.json"));
}

/// Inline unified-diff summary for the golden mismatch panic (bd-ub6x8.8).
fn summarize_golden_diff(actual: &str, expected: &str) -> String {
    let a: Vec<&str> = actual.lines().collect();
    let e: Vec<&str> = expected.lines().collect();
    let n = a.len().max(e.len());
    let mut first = None;
    let mut last = None;
    for i in 0..n {
        if a.get(i).copied().unwrap_or("") != e.get(i).copied().unwrap_or("") {
            first.get_or_insert(i);
            last = Some(i);
        }
    }
    let (Some(first), Some(last)) = (first, last) else {
        return format!(
            "    expected={} actual={} chars; no line-level diff (whitespace/encoding?)",
            expected.len(),
            actual.len()
        );
    };
    let pick = |v: &[&str], i: usize| -> String {
        v.get(i)
            .copied()
            .map(|s| s.chars().take(160).collect::<String>())
            .unwrap_or_else(|| "<EOF>".to_string())
    };
    format!(
        "    expected={} actual={} lines; first diff @ line {}, last @ line {}\n    -L{}: {}\n    +L{}: {}",
        e.len(),
        a.len(),
        first + 1,
        last + 1,
        first + 1,
        pick(&e, first),
        first + 1,
        pick(&a, first),
    )
}

/// Create deterministic JSON from serde-serializable type.
fn to_deterministic_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("serialization should succeed")
}

fn controller_pair(fast_controller: &str, slow_controller: &str) -> ControllerPairId {
    ControllerPairId {
        fast_controller: fast_controller.to_string(),
        slow_controller: slow_controller.to_string(),
    }
}

fn controller_profile(
    controller_id: &str,
    interval_millionths: i64,
    sample_count: u64,
    measured_epoch: u64,
) -> ControllerTimescaleProfile {
    ControllerTimescaleProfile {
        controller_id: controller_id.to_string(),
        observation_interval_millionths: interval_millionths,
        write_interval_millionths: interval_millionths,
        sample_count,
        measured_epoch,
    }
}

struct TimescaleCertificateSpec<'a> {
    certificate_id: &'a str,
    fast_controller: &'a str,
    slow_controller: &'a str,
    fast_interval_millionths: i64,
    slow_interval_millionths: i64,
    ratio_millionths: u64,
    verdict: SeparationVerdict,
    issued_epoch: u64,
}

fn timescale_certificate(spec: TimescaleCertificateSpec<'_>) -> TimescaleSeparationCertificate {
    let pair = controller_pair(spec.fast_controller, spec.slow_controller);
    TimescaleSeparationCertificate {
        schema_version: TIMESCALE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        certificate_id: spec.certificate_id.to_string(),
        pair: pair.clone(),
        ratio: TimescaleRatio {
            pair,
            ratio_millionths: spec.ratio_millionths,
            ratio_basis: RatioBasis::Observation,
        },
        verdict: spec.verdict,
        sufficient_threshold_millionths: DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
        marginal_threshold_millionths: DEFAULT_MARGINAL_RATIO_MILLIONTHS,
        fast_profile: controller_profile(
            spec.fast_controller,
            spec.fast_interval_millionths,
            1_000,
            spec.issued_epoch,
        ),
        slow_profile: controller_profile(
            spec.slow_controller,
            spec.slow_interval_millionths,
            200,
            spec.issued_epoch,
        ),
        issued_epoch: spec.issued_epoch,
        evidence_ids: vec![format!("evidence_{}", spec.certificate_id)],
    }
}

fn relaxed_policy_with_required_dimensions(
    required_dimensions: BTreeSet<ResourceDimension>,
) -> PublicationPolicy {
    PublicationPolicy {
        max_regression_millionths: 100_000,
        max_tail_risk_millionths: 500_000,
        max_utilisation_millionths: 900_000,
        min_samples: 30,
        min_observability_coverage: 800_000,
        required_evidence_kind: CertificateGovernanceEvidenceKind::ThresholdAndSampleHeuristic,
        required_dimensions,
    }
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
    let cert = timescale_certificate(TimescaleCertificateSpec {
        certificate_id: "cert_sufficient_001",
        fast_controller: "gc_controller",
        slow_controller: "batch_processor",
        fast_interval_millionths: 100_000,
        slow_interval_millionths: 5_000_000,
        ratio_millionths: 50_000_000,
        verdict: SeparationVerdict::Sufficient,
        issued_epoch: 1_640_995_200,
    });

    let json = to_deterministic_json(&cert);
    assert_golden("timescale_certificate_sufficient", &json);
}

#[test]
fn timescale_separation_certificate_marginal() {
    let cert = timescale_certificate(TimescaleCertificateSpec {
        certificate_id: "cert_marginal_002",
        fast_controller: "realtime_monitor",
        slow_controller: "periodic_cleanup",
        fast_interval_millionths: 50_000,
        slow_interval_millionths: 200_000,
        ratio_millionths: 4_000_000,
        verdict: SeparationVerdict::Marginal,
        issued_epoch: 1_640_995_300,
    });

    let json = to_deterministic_json(&cert);
    assert_golden("timescale_certificate_marginal", &json);
}

#[test]
fn timescale_separation_certificate_insufficient() {
    let cert = timescale_certificate(TimescaleCertificateSpec {
        certificate_id: "cert_insufficient_003",
        fast_controller: "high_freq_trader",
        slow_controller: "low_freq_trader",
        fast_interval_millionths: 1_000,
        slow_interval_millionths: 2_000,
        ratio_millionths: 2_000_000,
        verdict: SeparationVerdict::Insufficient,
        issued_epoch: 1_640_995_400,
    });

    let json = to_deterministic_json(&cert);
    assert_golden("timescale_certificate_insufficient", &json);
}

#[test]
fn certificate_bundle_mixed_verdicts() {
    let certificates = vec![
        timescale_certificate(TimescaleCertificateSpec {
            certificate_id: "bundle_cert_1",
            fast_controller: "controller_a",
            slow_controller: "controller_b",
            fast_interval_millionths: 10_000,
            slow_interval_millionths: 100_000,
            ratio_millionths: 10_000_000,
            verdict: SeparationVerdict::Sufficient,
            issued_epoch: 1_640_995_500,
        }),
        timescale_certificate(TimescaleCertificateSpec {
            certificate_id: "bundle_cert_2",
            fast_controller: "controller_a",
            slow_controller: "controller_c",
            fast_interval_millionths: 10_000,
            slow_interval_millionths: 30_000,
            ratio_millionths: 3_000_000,
            verdict: SeparationVerdict::Marginal,
            issued_epoch: 1_640_995_500,
        }),
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
    let mut required_dimensions = BTreeSet::new();
    required_dimensions.insert(ResourceDimension::CpuTime);
    required_dimensions.insert(ResourceDimension::HeapMemory);

    let mut evaluator =
        GovernanceEvaluator::new(relaxed_policy_with_required_dimensions(required_dimensions));
    evaluator.add_certificate(
        ResourceDimension::CpuTime,
        "web_server".to_string(),
        2_000_000,
        1_500_000,
        1_000,
    );
    evaluator.add_certificate(
        ResourceDimension::HeapMemory,
        "web_server".to_string(),
        500_000_000,
        320_000_000,
        1_000,
    );
    evaluator.add_regression(
        ResourceDimension::CpuTime,
        "web_server".to_string(),
        1_400_000,
        1_500_000,
    );
    evaluator.add_tail_risk(
        ResourceDimension::HeapMemory,
        "web_server".to_string(),
        2_500_000,
        2_000_000,
    );

    let receipt = evaluator.evaluate(SecurityEpoch::from_raw(42));
    assert_eq!(receipt.verdict, GovernanceVerdict::Approved);

    let json = to_deterministic_json(&receipt);
    assert_golden("governance_receipt_comprehensive", &json);
}

#[test]
fn governance_receipt_denial() {
    let mut policy = relaxed_policy_with_required_dimensions(BTreeSet::new());
    policy.max_utilisation_millionths = 1_000_000;
    let mut evaluator = GovernanceEvaluator::new(policy);
    evaluator.add_certificate(
        ResourceDimension::CpuTime,
        "overloaded_service".to_string(),
        1_000_000,
        1_200_000,
        1_000,
    );
    evaluator.add_regression(
        ResourceDimension::CpuTime,
        "overloaded_service".to_string(),
        800_000,
        1_200_000,
    );

    let receipt = evaluator.evaluate(SecurityEpoch::from_raw(43));
    assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);

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
