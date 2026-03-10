//! Integration tests for `descent_certificate_gate` module.
//!
//! Validates public API, serde contracts, determinism, gate evaluation logic,
//! batch processing, report aggregation, and rejection coverage.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::descent_certificate_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(900)
}

fn clean_cert(surface: SupportSurface) -> DescentCertificate {
    DescentCertificate::new(
        "cert-1",
        surface,
        980_000,
        900_000,
        Vec::new(),
        BTreeSet::new(),
    )
}

fn partial_cert(surface: SupportSurface) -> DescentCertificate {
    DescentCertificate::new(
        "cert-partial",
        surface,
        800_000, // below threshold
        900_000,
        Vec::new(),
        BTreeSet::new(),
    )
}

fn obstructed_cert(surface: SupportSurface) -> DescentCertificate {
    DescentCertificate::new(
        "cert-obs",
        surface,
        980_000,
        900_000,
        vec![Obstruction {
            kind: ObstructionKind::LocalMinimum,
            surface,
            region: "hot-loop".into(),
            severity_millionths: 200_000,
            description: "stuck at local minimum".into(),
        }],
        BTreeSet::new(),
    )
}

fn excluded_cert(surface: SupportSurface) -> DescentCertificate {
    DescentCertificate::new(
        "cert-excl",
        surface,
        980_000,
        900_000,
        Vec::new(),
        BTreeSet::from(["region-a".to_string()]),
    )
}

fn low_confidence_cert(surface: SupportSurface) -> DescentCertificate {
    DescentCertificate::new(
        "cert-lowconf",
        surface,
        980_000,
        700_000, // below MIN_DESCENT_CONFIDENCE
        Vec::new(),
        BTreeSet::new(),
    )
}

fn latency_claim() -> SupportClaim {
    SupportClaim {
        claim_id: "lat-1".into(),
        surface: SupportSurface::Latency,
        regions: BTreeSet::from(["region-a".to_string()]),
        description: "p99 latency < 10ms".into(),
        is_shipped_path: false,
    }
}

fn throughput_claim() -> SupportClaim {
    SupportClaim {
        claim_id: "thr-1".into(),
        surface: SupportSurface::Throughput,
        regions: BTreeSet::from(["region-b".to_string()]),
        description: "throughput > 100k ops/s".into(),
        is_shipped_path: false,
    }
}

fn shipped_claim() -> SupportClaim {
    SupportClaim {
        claim_id: "ship-1".into(),
        surface: SupportSurface::ShippedPath,
        regions: BTreeSet::from(["binary-x86".to_string()]),
        description: "shipped binary parity".into(),
        is_shipped_path: true,
    }
}

fn docs_claim() -> SupportClaim {
    SupportClaim {
        claim_id: "docs-1".into(),
        surface: SupportSurface::Documentation,
        regions: BTreeSet::from(["api-docs".to_string()]),
        description: "API docs accurate".into(),
        is_shipped_path: false,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("descent-certificate"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "descent_certificate_gate");
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn coverage_threshold_valid() {
    assert!(MIN_DESCENT_COVERAGE > 0);
    assert!(MIN_DESCENT_COVERAGE <= 1_000_000);
}

#[test]
fn confidence_threshold_valid() {
    assert!(MIN_DESCENT_CONFIDENCE > 0);
    assert!(MIN_DESCENT_CONFIDENCE <= 1_000_000);
}

#[test]
fn max_obstructions_is_zero() {
    assert_eq!(MAX_OBSTRUCTIONS_ALLOWED, 0);
}

// ---------------------------------------------------------------------------
// SupportSurface
// ---------------------------------------------------------------------------

#[test]
fn surface_all_count() {
    assert_eq!(SupportSurface::ALL.len(), 7);
}

#[test]
fn surface_names_unique() {
    let names: BTreeSet<&str> = SupportSurface::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), SupportSurface::ALL.len());
}

#[test]
fn surface_display_matches_as_str() {
    for s in SupportSurface::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn surface_serde_all() {
    for s in SupportSurface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: SupportSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// ObstructionKind
// ---------------------------------------------------------------------------

#[test]
fn obstruction_kind_all_count() {
    assert_eq!(ObstructionKind::ALL.len(), 5);
}

#[test]
fn obstruction_kind_names_unique() {
    let names: BTreeSet<&str> = ObstructionKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), ObstructionKind::ALL.len());
}

#[test]
fn obstruction_kind_display() {
    for k in ObstructionKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn obstruction_kind_serde_all() {
    for k in ObstructionKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: ObstructionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// Obstruction
// ---------------------------------------------------------------------------

#[test]
fn obstruction_construction() {
    let o = Obstruction {
        kind: ObstructionKind::SaddlePoint,
        surface: SupportSurface::Memory,
        region: "heap-alloc".into(),
        severity_millionths: 500_000,
        description: "saddle in memory landscape".into(),
    };
    assert_eq!(o.kind, ObstructionKind::SaddlePoint);
    assert_eq!(o.surface, SupportSurface::Memory);
}

#[test]
fn obstruction_serde_roundtrip() {
    let o = Obstruction {
        kind: ObstructionKind::Discontinuity,
        surface: SupportSurface::Throughput,
        region: "io-path".into(),
        severity_millionths: 750_000,
        description: "cliff in throughput".into(),
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: Obstruction = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

// ---------------------------------------------------------------------------
// DescentCertificate
// ---------------------------------------------------------------------------

#[test]
fn cert_clean_properties() {
    let c = clean_cert(SupportSurface::Latency);
    assert!(c.is_obstruction_free());
    assert!(c.meets_coverage_threshold(MIN_DESCENT_COVERAGE));
    assert!(c.meets_confidence_threshold(MIN_DESCENT_CONFIDENCE));
}

#[test]
fn cert_obstructed_properties() {
    let c = obstructed_cert(SupportSurface::Latency);
    assert!(!c.is_obstruction_free());
    assert_eq!(c.obstructions.len(), 1);
}

#[test]
fn cert_partial_coverage() {
    let c = partial_cert(SupportSurface::Latency);
    assert!(!c.meets_coverage_threshold(MIN_DESCENT_COVERAGE));
    assert!(c.meets_coverage_threshold(800_000));
}

#[test]
fn cert_low_confidence() {
    let c = low_confidence_cert(SupportSurface::Latency);
    assert!(!c.meets_confidence_threshold(MIN_DESCENT_CONFIDENCE));
}

#[test]
fn cert_excluded_regions() {
    let c = excluded_cert(SupportSurface::Latency);
    assert!(c.excluded_regions.contains("region-a"));
}

#[test]
fn cert_hash_deterministic() {
    let c1 = clean_cert(SupportSurface::Latency);
    let c2 = clean_cert(SupportSurface::Latency);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn cert_different_surface_different_hash() {
    let c1 = clean_cert(SupportSurface::Latency);
    let c2 = clean_cert(SupportSurface::Throughput);
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn cert_serde_roundtrip() {
    let c = clean_cert(SupportSurface::Throughput);
    let json = serde_json::to_string(&c).unwrap();
    let back: DescentCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn cert_obstructed_serde_roundtrip() {
    let c = obstructed_cert(SupportSurface::Memory);
    let json = serde_json::to_string(&c).unwrap();
    let back: DescentCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// GateRejection
// ---------------------------------------------------------------------------

#[test]
fn rejection_tags_unique() {
    let rejections = vec![
        GateRejection::NoCertificate,
        GateRejection::SurfaceMismatch {
            claim_surface: SupportSurface::Latency,
            cert_surface: SupportSurface::Memory,
        },
        GateRejection::InsufficientCoverage {
            coverage_millionths: 0,
            threshold_millionths: 0,
        },
        GateRejection::InsufficientConfidence {
            confidence_millionths: 0,
            threshold_millionths: 0,
        },
        GateRejection::ActiveObstructions { count: 1 },
        GateRejection::UncoveredRegions {
            regions: BTreeSet::new(),
        },
        GateRejection::NoParityEvidence,
    ];
    let tags: BTreeSet<&str> = rejections.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 7);
}

#[test]
fn rejection_display_content() {
    let r = GateRejection::InsufficientCoverage {
        coverage_millionths: 800_000,
        threshold_millionths: 950_000,
    };
    assert!(r.to_string().contains("800000"));
}

#[test]
fn rejection_serde_all_variants() {
    let rejections = vec![
        GateRejection::NoCertificate,
        GateRejection::SurfaceMismatch {
            claim_surface: SupportSurface::Correctness,
            cert_surface: SupportSurface::Compatibility,
        },
        GateRejection::InsufficientCoverage {
            coverage_millionths: 500_000,
            threshold_millionths: 950_000,
        },
        GateRejection::InsufficientConfidence {
            confidence_millionths: 600_000,
            threshold_millionths: 850_000,
        },
        GateRejection::ActiveObstructions { count: 2 },
        GateRejection::UncoveredRegions {
            regions: BTreeSet::from(["r1".to_string()]),
        },
        GateRejection::NoParityEvidence,
    ];
    for r in &rejections {
        let json = serde_json::to_string(r).unwrap();
        let back: GateRejection = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_supported_properties() {
    let v = GateVerdict::Supported {
        claim_id: "x".into(),
        certificate_id: "c1".into(),
    };
    assert!(v.is_supported());
    assert!(!v.is_rejected());
    assert_eq!(v.claim_id(), "x");
    assert_eq!(v.tag(), "supported");
}

#[test]
fn verdict_rejected_properties() {
    let v = GateVerdict::Rejected {
        claim_id: "y".into(),
        reasons: vec![GateRejection::NoCertificate],
    };
    assert!(v.is_rejected());
    assert!(!v.is_supported());
    assert_eq!(v.tag(), "rejected");
}

#[test]
fn verdict_no_certificate_properties() {
    let v = GateVerdict::NoCertificate {
        claim_id: "z".into(),
    };
    assert!(!v.is_supported());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "no_certificate");
}

#[test]
fn verdict_display_supported() {
    let v = GateVerdict::Supported {
        claim_id: "test".into(),
        certificate_id: "cert-1".into(),
    };
    assert!(v.to_string().contains("SUPPORTED"));
}

#[test]
fn verdict_display_rejected() {
    let v = GateVerdict::Rejected {
        claim_id: "test".into(),
        reasons: vec![GateRejection::NoCertificate],
    };
    assert!(v.to_string().contains("REJECTED"));
}

#[test]
fn verdict_serde_supported() {
    let v = GateVerdict::Supported {
        claim_id: "x".into(),
        certificate_id: "c1".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_serde_rejected() {
    let v = GateVerdict::Rejected {
        claim_id: "y".into(),
        reasons: vec![GateRejection::ActiveObstructions { count: 2 }],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// DescentGateConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let c = DescentGateConfig::default_config();
    assert_eq!(c.min_coverage, MIN_DESCENT_COVERAGE);
    assert_eq!(c.min_confidence, MIN_DESCENT_CONFIDENCE);
    assert_eq!(c.max_obstructions, MAX_OBSTRUCTIONS_ALLOWED);
    assert!(c.require_parity_for_shipped);
}

#[test]
fn config_default_trait() {
    assert_eq!(DescentGateConfig::default(), DescentGateConfig::default_config());
}

#[test]
fn config_permissive() {
    let c = DescentGateConfig::permissive();
    assert_eq!(c.min_coverage, 0);
    assert_eq!(c.min_confidence, 0);
    assert_eq!(c.max_obstructions, usize::MAX);
    assert!(!c.require_parity_for_shipped);
}

#[test]
fn config_serde_roundtrip() {
    let c = DescentGateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: DescentGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// DescentGate — basic evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_supports_clean_cert() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(&latency_claim(), Some(&clean_cert(SupportSurface::Latency)), false);
    assert!(v.is_supported());
}

#[test]
fn gate_no_certificate() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(&latency_claim(), None, false);
    assert!(matches!(v, GateVerdict::NoCertificate { .. }));
}

#[test]
fn gate_rejects_surface_mismatch() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &latency_claim(),
        Some(&clean_cert(SupportSurface::Memory)),
        false,
    );
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_low_coverage() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &latency_claim(),
        Some(&partial_cert(SupportSurface::Latency)),
        false,
    );
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_low_confidence() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &latency_claim(),
        Some(&low_confidence_cert(SupportSurface::Latency)),
        false,
    );
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_obstructed() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &latency_claim(),
        Some(&obstructed_cert(SupportSurface::Latency)),
        false,
    );
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_excluded_region() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &latency_claim(), // claims region-a
        Some(&excluded_cert(SupportSurface::Latency)), // excludes region-a
        false,
    );
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_shipped_no_parity() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &shipped_claim(),
        Some(&clean_cert(SupportSurface::ShippedPath)),
        false,
    );
    assert!(v.is_rejected());
}

#[test]
fn gate_supports_shipped_with_parity() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &shipped_claim(),
        Some(&clean_cert(SupportSurface::ShippedPath)),
        true,
    );
    assert!(v.is_supported());
}

#[test]
fn gate_supports_non_shipped_no_parity() {
    let gate = DescentGate::with_defaults();
    let v = gate.evaluate(
        &docs_claim(),
        Some(&clean_cert(SupportSurface::Documentation)),
        false,
    );
    assert!(v.is_supported());
}

// ---------------------------------------------------------------------------
// DescentGate — permissive config
// ---------------------------------------------------------------------------

#[test]
fn permissive_admits_obstructed() {
    let gate = DescentGate::with_config(DescentGateConfig::permissive());
    let v = gate.evaluate(
        &latency_claim(),
        Some(&obstructed_cert(SupportSurface::Latency)),
        false,
    );
    assert!(v.is_supported());
}

#[test]
fn permissive_admits_low_coverage() {
    let gate = DescentGate::with_config(DescentGateConfig::permissive());
    let v = gate.evaluate(
        &latency_claim(),
        Some(&partial_cert(SupportSurface::Latency)),
        false,
    );
    assert!(v.is_supported());
}

#[test]
fn permissive_admits_shipped_no_parity() {
    let gate = DescentGate::with_config(DescentGateConfig::permissive());
    let v = gate.evaluate(
        &shipped_claim(),
        Some(&clean_cert(SupportSurface::ShippedPath)),
        false,
    );
    assert!(v.is_supported());
}

// ---------------------------------------------------------------------------
// Batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn batch_empty() {
    let gate = DescentGate::with_defaults();
    let results = gate.evaluate_batch(&[], &BTreeMap::new(), &BTreeSet::new());
    assert!(results.is_empty());
}

#[test]
fn batch_all_supported() {
    let gate = DescentGate::with_defaults();
    let claims = vec![latency_claim(), throughput_claim()];
    let mut certs = BTreeMap::new();
    certs.insert("lat-1".to_string(), clean_cert(SupportSurface::Latency));
    certs.insert("thr-1".to_string(), clean_cert(SupportSurface::Throughput));
    let results = gate.evaluate_batch(&claims, &certs, &BTreeSet::new());
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|v| v.is_supported()));
}

#[test]
fn batch_mixed_results() {
    let gate = DescentGate::with_defaults();
    let claims = vec![latency_claim(), throughput_claim(), shipped_claim()];
    let mut certs = BTreeMap::new();
    certs.insert("lat-1".to_string(), clean_cert(SupportSurface::Latency));
    // thr-1 has no cert
    certs.insert("ship-1".to_string(), clean_cert(SupportSurface::ShippedPath));
    let parity = BTreeSet::from(["ship-1".to_string()]);
    let results = gate.evaluate_batch(&claims, &certs, &parity);
    assert_eq!(results.len(), 3);
    assert!(results[0].is_supported()); // latency
    assert!(matches!(results[1], GateVerdict::NoCertificate { .. })); // throughput
    assert!(results[2].is_supported()); // shipped with parity
}

#[test]
fn batch_preserves_order() {
    let gate = DescentGate::with_defaults();
    let claims = vec![latency_claim(), throughput_claim(), docs_claim()];
    let results = gate.evaluate_batch(&claims, &BTreeMap::new(), &BTreeSet::new());
    assert_eq!(results[0].claim_id(), "lat-1");
    assert_eq!(results[1].claim_id(), "thr-1");
    assert_eq!(results[2].claim_id(), "docs-1");
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

#[test]
fn report_empty() {
    let r = GateReport::new(epoch(), Vec::new());
    assert_eq!(r.total_count(), 0);
    assert_eq!(r.support_rate(), 0);
    assert!(!r.all_supported());
    assert!(!r.has_rejections());
}

#[test]
fn report_schema_version() {
    let r = GateReport::new(epoch(), Vec::new());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_all_supported() {
    let verdicts = vec![
        GateVerdict::Supported {
            claim_id: "a".into(),
            certificate_id: "c1".into(),
        },
        GateVerdict::Supported {
            claim_id: "b".into(),
            certificate_id: "c2".into(),
        },
    ];
    let r = GateReport::new(epoch(), verdicts);
    assert!(r.all_supported());
    assert_eq!(r.support_rate(), 1_000_000);
    assert!(!r.has_rejections());
}

#[test]
fn report_mixed() {
    let verdicts = vec![
        GateVerdict::Supported {
            claim_id: "a".into(),
            certificate_id: "c1".into(),
        },
        GateVerdict::Rejected {
            claim_id: "b".into(),
            reasons: vec![GateRejection::NoCertificate],
        },
        GateVerdict::NoCertificate {
            claim_id: "c".into(),
        },
    ];
    let r = GateReport::new(epoch(), verdicts);
    assert_eq!(r.total_count(), 3);
    assert_eq!(r.supported_count, 1);
    assert_eq!(r.rejected_count, 1);
    assert_eq!(r.no_certificate_count, 1);
    assert!(r.has_rejections());
    assert!(!r.all_supported());
}

#[test]
fn report_hash_deterministic() {
    let v = vec![GateVerdict::Supported {
        claim_id: "a".into(),
        certificate_id: "c1".into(),
    }];
    let r1 = GateReport::new(epoch(), v.clone());
    let r2 = GateReport::new(epoch(), v);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_different_epoch_different_hash() {
    let v = vec![GateVerdict::Supported {
        claim_id: "a".into(),
        certificate_id: "c1".into(),
    }];
    let r1 = GateReport::new(SecurityEpoch::from_raw(100), v.clone());
    let r2 = GateReport::new(SecurityEpoch::from_raw(200), v);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let verdicts = vec![
        GateVerdict::Supported {
            claim_id: "a".into(),
            certificate_id: "c1".into(),
        },
        GateVerdict::Rejected {
            claim_id: "b".into(),
            reasons: vec![
                GateRejection::ActiveObstructions { count: 1 },
                GateRejection::InsufficientCoverage {
                    coverage_millionths: 500_000,
                    threshold_millionths: 950_000,
                },
            ],
        },
    ];
    let r = GateReport::new(epoch(), verdicts);
    let json = serde_json::to_string(&r).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn full_gate_workflow() {
    let gate = DescentGate::with_defaults();

    let claims = vec![
        latency_claim(),
        throughput_claim(),
        shipped_claim(),
        docs_claim(),
    ];

    let mut certs = BTreeMap::new();
    certs.insert("lat-1".to_string(), clean_cert(SupportSurface::Latency));
    certs.insert(
        "thr-1".to_string(),
        obstructed_cert(SupportSurface::Throughput),
    );
    certs.insert("ship-1".to_string(), clean_cert(SupportSurface::ShippedPath));
    certs.insert(
        "docs-1".to_string(),
        clean_cert(SupportSurface::Documentation),
    );

    let parity = BTreeSet::from(["ship-1".to_string()]);
    let verdicts = gate.evaluate_batch(&claims, &certs, &parity);
    let report = GateReport::new(epoch(), verdicts);

    assert_eq!(report.total_count(), 4);
    assert_eq!(report.supported_count, 3); // lat, ship, docs
    assert_eq!(report.rejected_count, 1); // thr (obstructed)
    assert!(report.has_rejections());
}

#[test]
fn gate_serde_roundtrip() {
    let gate = DescentGate::with_defaults();
    let json = serde_json::to_string(&gate).unwrap();
    let back: DescentGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}
