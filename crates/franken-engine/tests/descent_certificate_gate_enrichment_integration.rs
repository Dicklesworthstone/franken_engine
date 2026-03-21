//! Enrichment integration tests for `descent_certificate_gate` module.
//!
//! Tests additional scenarios: boundary conditions, batch evaluation,
//! report lifecycle, rejection chaining, Display/serde coverage.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::descent_certificate_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_cert(
    id: &str,
    surface: SupportSurface,
    coverage: u64,
    confidence: u64,
    obstructions: Vec<Obstruction>,
    excluded: BTreeSet<String>,
) -> DescentCertificate {
    DescentCertificate::new(id, surface, coverage, confidence, obstructions, excluded)
}

fn make_claim(
    id: &str,
    surface: SupportSurface,
    regions: BTreeSet<String>,
    shipped: bool,
) -> SupportClaim {
    SupportClaim {
        claim_id: id.into(),
        surface,
        regions,
        description: format!("claim {id}"),
        is_shipped_path: shipped,
    }
}

fn default_gate() -> DescentGate {
    DescentGate::with_defaults()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_min_coverage_within_bounds() {
    assert!(MIN_DESCENT_COVERAGE > 0 && MIN_DESCENT_COVERAGE <= 1_000_000);
}

#[test]
fn constants_min_confidence_within_bounds() {
    assert!(MIN_DESCENT_CONFIDENCE > 0 && MIN_DESCENT_CONFIDENCE <= 1_000_000);
}

#[test]
fn constants_max_obstructions_zero() {
    assert_eq!(MAX_OBSTRUCTIONS_ALLOWED, 0);
}

#[test]
fn constants_schema_version_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn constants_component_name_matches() {
    assert_eq!(COMPONENT, "descent_certificate_gate");
}

#[test]
fn constants_bead_and_policy_ids() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// SupportSurface
// ---------------------------------------------------------------------------

#[test]
fn surface_all_variants_count() {
    assert_eq!(SupportSurface::ALL.len(), 7);
}

#[test]
fn surface_display_distinctness() {
    let displays: BTreeSet<String> = SupportSurface::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn surface_serde_roundtrip_all() {
    for s in SupportSurface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: SupportSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn surface_ord_is_consistent() {
    assert!(SupportSurface::Latency < SupportSurface::ShippedPath);
}

// ---------------------------------------------------------------------------
// ObstructionKind
// ---------------------------------------------------------------------------

#[test]
fn obstruction_kind_all_count() {
    assert_eq!(ObstructionKind::ALL.len(), 5);
}

#[test]
fn obstruction_kind_display_distinctness() {
    let displays: BTreeSet<String> = ObstructionKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn obstruction_kind_serde_roundtrip_all() {
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
fn obstruction_serde_roundtrip() {
    let obs = Obstruction {
        kind: ObstructionKind::SaddlePoint,
        surface: SupportSurface::Memory,
        region: "heap-alloc".into(),
        severity_millionths: 400_000,
        description: "saddle point in memory surface".into(),
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: Obstruction = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn obstruction_clone_equality() {
    let obs = Obstruction {
        kind: ObstructionKind::Interference,
        surface: SupportSurface::Correctness,
        region: "reg-1".into(),
        severity_millionths: 100_000,
        description: "conflict".into(),
    };
    let cloned = obs.clone();
    assert_eq!(obs, cloned);
}

// ---------------------------------------------------------------------------
// DescentCertificate
// ---------------------------------------------------------------------------

#[test]
fn cert_hash_deterministic_same_inputs() {
    let c1 = make_cert(
        "cert-x",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let c2 = make_cert(
        "cert-x",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn cert_hash_differs_on_id() {
    let c1 = make_cert(
        "cert-a",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let c2 = make_cert(
        "cert-b",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn cert_hash_differs_on_surface() {
    let c1 = make_cert(
        "cert-x",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let c2 = make_cert(
        "cert-x",
        SupportSurface::Throughput,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn cert_hash_differs_on_coverage() {
    let c1 = make_cert(
        "cert-x",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let c2 = make_cert(
        "cert-x",
        SupportSurface::Latency,
        500_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn cert_is_obstruction_free_when_empty() {
    let c = make_cert(
        "c",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    assert!(c.is_obstruction_free());
}

#[test]
fn cert_is_not_obstruction_free_when_has_obstructions() {
    let obs = Obstruction {
        kind: ObstructionKind::LocalMinimum,
        surface: SupportSurface::Latency,
        region: "r".into(),
        severity_millionths: 100_000,
        description: "d".into(),
    };
    let c = make_cert(
        "c",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![obs],
        BTreeSet::new(),
    );
    assert!(!c.is_obstruction_free());
}

#[test]
fn cert_meets_coverage_boundary() {
    let c = make_cert(
        "c",
        SupportSurface::Latency,
        950_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    assert!(c.meets_coverage_threshold(950_000));
    assert!(!c.meets_coverage_threshold(950_001));
}

#[test]
fn cert_meets_confidence_boundary() {
    let c = make_cert(
        "c",
        SupportSurface::Latency,
        960_000,
        850_000,
        vec![],
        BTreeSet::new(),
    );
    assert!(c.meets_confidence_threshold(850_000));
    assert!(!c.meets_confidence_threshold(850_001));
}

#[test]
fn cert_serde_roundtrip() {
    let c = make_cert(
        "cert-serde",
        SupportSurface::Compatibility,
        980_000,
        920_000,
        vec![],
        BTreeSet::from(["excl-region".to_string()]),
    );
    let json = serde_json::to_string(&c).unwrap();
    let back: DescentCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// SupportClaim
// ---------------------------------------------------------------------------

#[test]
fn support_claim_serde_roundtrip() {
    let claim = make_claim(
        "claim-1",
        SupportSurface::Documentation,
        BTreeSet::from(["docs-api".to_string()]),
        false,
    );
    let json = serde_json::to_string(&claim).unwrap();
    let back: SupportClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(claim, back);
}

#[test]
fn support_claim_shipped_path_flag() {
    let claim = make_claim("ship-1", SupportSurface::ShippedPath, BTreeSet::new(), true);
    assert!(claim.is_shipped_path);
}

// ---------------------------------------------------------------------------
// GateRejection
// ---------------------------------------------------------------------------

#[test]
fn gate_rejection_tag_distinctness() {
    let rejections = [
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
fn gate_rejection_display_all_nonempty() {
    let rejections = [
        GateRejection::NoCertificate,
        GateRejection::SurfaceMismatch {
            claim_surface: SupportSurface::Latency,
            cert_surface: SupportSurface::Memory,
        },
        GateRejection::InsufficientCoverage {
            coverage_millionths: 800_000,
            threshold_millionths: 950_000,
        },
        GateRejection::InsufficientConfidence {
            confidence_millionths: 700_000,
            threshold_millionths: 850_000,
        },
        GateRejection::ActiveObstructions { count: 3 },
        GateRejection::UncoveredRegions {
            regions: BTreeSet::from(["r1".to_string()]),
        },
        GateRejection::NoParityEvidence,
    ];
    let displays: BTreeSet<String> = rejections.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn gate_rejection_serde_all_variants() {
    let rejections = vec![
        GateRejection::NoCertificate,
        GateRejection::NoParityEvidence,
        GateRejection::ActiveObstructions { count: 5 },
        GateRejection::InsufficientCoverage {
            coverage_millionths: 100,
            threshold_millionths: 200,
        },
        GateRejection::InsufficientConfidence {
            confidence_millionths: 10,
            threshold_millionths: 20,
        },
        GateRejection::SurfaceMismatch {
            claim_surface: SupportSurface::Throughput,
            cert_surface: SupportSurface::Correctness,
        },
        GateRejection::UncoveredRegions {
            regions: BTreeSet::from(["a".to_string(), "b".to_string()]),
        },
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
fn verdict_supported_methods() {
    let v = GateVerdict::Supported {
        claim_id: "c1".into(),
        certificate_id: "cert-1".into(),
    };
    assert!(v.is_supported());
    assert!(!v.is_rejected());
    assert_eq!(v.claim_id(), "c1");
    assert_eq!(v.tag(), "supported");
}

#[test]
fn verdict_rejected_methods() {
    let v = GateVerdict::Rejected {
        claim_id: "c2".into(),
        reasons: vec![GateRejection::NoCertificate],
    };
    assert!(v.is_rejected());
    assert!(!v.is_supported());
    assert_eq!(v.claim_id(), "c2");
    assert_eq!(v.tag(), "rejected");
}

#[test]
fn verdict_no_certificate_methods() {
    let v = GateVerdict::NoCertificate {
        claim_id: "c3".into(),
    };
    assert!(!v.is_supported());
    assert!(!v.is_rejected());
    assert_eq!(v.claim_id(), "c3");
    assert_eq!(v.tag(), "no_certificate");
}

#[test]
fn verdict_display_distinctness() {
    let verdicts = [
        GateVerdict::Supported {
            claim_id: "a".into(),
            certificate_id: "cert".into(),
        },
        GateVerdict::Rejected {
            claim_id: "b".into(),
            reasons: vec![],
        },
        GateVerdict::NoCertificate {
            claim_id: "c".into(),
        },
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn verdict_serde_roundtrip_all_variants() {
    let verdicts = vec![
        GateVerdict::Supported {
            claim_id: "x".into(),
            certificate_id: "y".into(),
        },
        GateVerdict::Rejected {
            claim_id: "z".into(),
            reasons: vec![
                GateRejection::NoCertificate,
                GateRejection::NoParityEvidence,
            ],
        },
        GateVerdict::NoCertificate {
            claim_id: "w".into(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// DescentGateConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_matches_constants() {
    let cfg = DescentGateConfig::default();
    assert_eq!(cfg.min_coverage, MIN_DESCENT_COVERAGE);
    assert_eq!(cfg.min_confidence, MIN_DESCENT_CONFIDENCE);
    assert_eq!(cfg.max_obstructions, MAX_OBSTRUCTIONS_ALLOWED);
    assert!(cfg.require_parity_for_shipped);
}

#[test]
fn config_permissive_zero_thresholds() {
    let cfg = DescentGateConfig::permissive();
    assert_eq!(cfg.min_coverage, 0);
    assert_eq!(cfg.min_confidence, 0);
    assert_eq!(cfg.max_obstructions, usize::MAX);
    assert!(!cfg.require_parity_for_shipped);
}

#[test]
fn config_serde_roundtrip() {
    let cfg = DescentGateConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: DescentGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// DescentGate — Evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_evaluate_supports_clean_cert() {
    let gate = default_gate();
    let claim = make_claim("cl-1", SupportSurface::Latency, BTreeSet::new(), false);
    let cert = make_cert(
        "cert-1",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_supported());
}

#[test]
fn gate_evaluate_no_certificate() {
    let gate = default_gate();
    let claim = make_claim("cl-2", SupportSurface::Latency, BTreeSet::new(), false);
    let v = gate.evaluate(&claim, None, false);
    assert!(matches!(v, GateVerdict::NoCertificate { .. }));
}

#[test]
fn gate_evaluate_rejects_surface_mismatch() {
    let gate = default_gate();
    let claim = make_claim("cl-3", SupportSurface::Latency, BTreeSet::new(), false);
    let cert = make_cert(
        "cert-1",
        SupportSurface::Memory,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_rejected());
}

#[test]
fn gate_evaluate_rejects_low_coverage() {
    let gate = default_gate();
    let claim = make_claim("cl-4", SupportSurface::Latency, BTreeSet::new(), false);
    let cert = make_cert(
        "cert-1",
        SupportSurface::Latency,
        800_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_rejected());
}

#[test]
fn gate_evaluate_rejects_low_confidence() {
    let gate = default_gate();
    let claim = make_claim("cl-5", SupportSurface::Latency, BTreeSet::new(), false);
    let cert = make_cert(
        "cert-1",
        SupportSurface::Latency,
        960_000,
        700_000,
        vec![],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_rejected());
}

#[test]
fn gate_evaluate_rejects_obstructed_cert() {
    let gate = default_gate();
    let claim = make_claim("cl-6", SupportSurface::Latency, BTreeSet::new(), false);
    let obs = Obstruction {
        kind: ObstructionKind::Discontinuity,
        surface: SupportSurface::Latency,
        region: "r".into(),
        severity_millionths: 200_000,
        description: "d".into(),
    };
    let cert = make_cert(
        "cert-1",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![obs],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_rejected());
}

#[test]
fn gate_evaluate_rejects_uncovered_regions() {
    let gate = default_gate();
    let claim = make_claim(
        "cl-7",
        SupportSurface::Latency,
        BTreeSet::from(["region-a".to_string()]),
        false,
    );
    let cert = make_cert(
        "cert-1",
        SupportSurface::Latency,
        960_000,
        900_000,
        vec![],
        BTreeSet::from(["region-a".to_string()]),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_rejected());
}

#[test]
fn gate_evaluate_shipped_without_parity_rejected() {
    let gate = default_gate();
    let claim = make_claim("cl-8", SupportSurface::ShippedPath, BTreeSet::new(), true);
    let cert = make_cert(
        "cert-1",
        SupportSurface::ShippedPath,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_rejected());
}

#[test]
fn gate_evaluate_shipped_with_parity_supported() {
    let gate = default_gate();
    let claim = make_claim("cl-9", SupportSurface::ShippedPath, BTreeSet::new(), true);
    let cert = make_cert(
        "cert-1",
        SupportSurface::ShippedPath,
        960_000,
        900_000,
        vec![],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), true);
    assert!(v.is_supported());
}

#[test]
fn gate_permissive_accepts_everything() {
    let gate = DescentGate::with_config(DescentGateConfig::permissive());
    let obs = Obstruction {
        kind: ObstructionKind::Infeasibility,
        surface: SupportSurface::Latency,
        region: "r".into(),
        severity_millionths: 999_999,
        description: "d".into(),
    };
    let claim = make_claim("cl-10", SupportSurface::Latency, BTreeSet::new(), true);
    let cert = make_cert(
        "cert-1",
        SupportSurface::Latency,
        100,
        100,
        vec![obs],
        BTreeSet::new(),
    );
    let v = gate.evaluate(&claim, Some(&cert), false);
    assert!(v.is_supported());
}

// ---------------------------------------------------------------------------
// DescentGate — Batch Evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_batch_empty_claims() {
    let gate = default_gate();
    let verdicts = gate.evaluate_batch(&[], &BTreeMap::new(), &BTreeSet::new());
    assert!(verdicts.is_empty());
}

#[test]
fn gate_batch_mixed_results() {
    let gate = default_gate();
    let claims = vec![
        make_claim("cl-a", SupportSurface::Latency, BTreeSet::new(), false),
        make_claim("cl-b", SupportSurface::Memory, BTreeSet::new(), false),
    ];
    let mut certs = BTreeMap::new();
    certs.insert(
        "cl-a".to_string(),
        make_cert(
            "cert-a",
            SupportSurface::Latency,
            960_000,
            900_000,
            vec![],
            BTreeSet::new(),
        ),
    );
    // cl-b has no certificate
    let verdicts = gate.evaluate_batch(&claims, &certs, &BTreeSet::new());
    assert_eq!(verdicts.len(), 2);
    assert!(verdicts[0].is_supported());
    assert!(matches!(verdicts[1], GateVerdict::NoCertificate { .. }));
}

// ---------------------------------------------------------------------------
// DescentGate — serde
// ---------------------------------------------------------------------------

#[test]
fn gate_serde_roundtrip() {
    let gate = default_gate();
    let json = serde_json::to_string(&gate).unwrap();
    let back: DescentGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

#[test]
fn gate_with_config_schema_version() {
    let gate = DescentGate::with_config(DescentGateConfig::permissive());
    assert_eq!(gate.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

#[test]
fn report_empty_verdicts() {
    let r = GateReport::new(epoch(1), vec![]);
    assert_eq!(r.total_count(), 0);
    assert_eq!(r.supported_count, 0);
    assert_eq!(r.rejected_count, 0);
    assert_eq!(r.no_certificate_count, 0);
    assert!(!r.all_supported());
    assert!(!r.has_rejections());
    assert_eq!(r.support_rate(), 0);
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
    let r = GateReport::new(epoch(2), verdicts);
    assert!(r.all_supported());
    assert!(!r.has_rejections());
    assert_eq!(r.support_rate(), 1_000_000);
    assert_eq!(r.total_count(), 2);
}

#[test]
fn report_mixed_counts() {
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
    let r = GateReport::new(epoch(3), verdicts);
    assert_eq!(r.supported_count, 1);
    assert_eq!(r.rejected_count, 1);
    assert_eq!(r.no_certificate_count, 1);
    assert_eq!(r.total_count(), 3);
    assert!(!r.all_supported());
    assert!(r.has_rejections());
    // support_rate = 1/3 * 1_000_000 = 333_333
    assert_eq!(r.support_rate(), 333_333);
}

#[test]
fn report_hash_deterministic() {
    let v = vec![GateVerdict::Supported {
        claim_id: "a".into(),
        certificate_id: "c1".into(),
    }];
    let r1 = GateReport::new(epoch(1), v.clone());
    let r2 = GateReport::new(epoch(1), v);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_hash_differs_on_epoch() {
    let v = vec![GateVerdict::Supported {
        claim_id: "a".into(),
        certificate_id: "c1".into(),
    }];
    let r1 = GateReport::new(epoch(1), v.clone());
    let r2 = GateReport::new(epoch(2), v);
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
            reasons: vec![GateRejection::ActiveObstructions { count: 2 }],
        },
    ];
    let r = GateReport::new(epoch(5), verdicts);
    let json = serde_json::to_string(&r).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn report_schema_version_matches_constant() {
    let r = GateReport::new(epoch(1), vec![]);
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}
