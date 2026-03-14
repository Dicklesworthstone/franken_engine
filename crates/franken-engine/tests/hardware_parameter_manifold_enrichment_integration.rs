//! Enrichment integration tests for hardware_parameter_manifold.

use frankenengine_engine::hardware_parameter_manifold::{
    BEAD_ID, COMPONENT, DEFAULT_SIMILARITY_THRESHOLD, HardwareAxis, HardwareAxisDomain,
    HardwareFingerprint, MAX_CLASS_SIZE, MAX_HARDWARE_AXES, Obligation, ObligationGraph,
    ObligationReport, ObligationStatus, OptimizationQuestion, POLICY_ID, SCHEMA_VERSION,
    SymmetryClass, SymmetryReason, SymmetryRefusal, default_hardware_axes,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_axis(key: &str, domain: HardwareAxisDomain) -> HardwareAxis {
    HardwareAxis::new(key, domain, 0, 1_000_000, true, format!("Test axis {key}"))
}

fn make_fingerprint(id: &str, values: &[(&str, u64)]) -> HardwareFingerprint {
    let vals: BTreeMap<String, u64> = values.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    HardwareFingerprint::new(id, format!("Test {id}"), vals)
}

fn make_question(id: &str, axes: &[&str]) -> OptimizationQuestion {
    let relevant: BTreeSet<String> = axes.iter().map(|a| a.to_string()).collect();
    OptimizationQuestion::new(id, format!("Question {id}"), relevant)
}

fn simple_graph() -> ObligationGraph {
    let mut g = ObligationGraph::with_defaults();
    g.add_axis(make_axis("core_count", HardwareAxisDomain::Microarch));
    g.add_axis(make_axis("mem_bw", HardwareAxisDomain::Memory));
    g.add_fingerprint(make_fingerprint(
        "fp-a",
        &[("core_count", 500_000), ("mem_bw", 600_000)],
    ));
    g.add_fingerprint(make_fingerprint(
        "fp-b",
        &[("core_count", 510_000), ("mem_bw", 610_000)],
    ));
    g.add_question(make_question("q1", &["core_count"]));
    g
}

// ---------------------------------------------------------------------------
// Copy semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_domain_copy() {
    let a = HardwareAxisDomain::Microarch;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_obligation_status_copy() {
    let a = ObligationStatus::Pending;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Clone independence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_clone() {
    let a = make_axis("core_count", HardwareAxisDomain::Microarch);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_fingerprint_clone() {
    let a = make_fingerprint("fp-a", &[("core_count", 500_000)]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_question_clone() {
    let a = make_question("q1", &["core_count"]);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_obligation_clone() {
    let a = Obligation::pending("fp-a", "q1");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_symmetry_reason_clone() {
    let a = SymmetryReason::WithinThreshold {
        max_distance_millionths: 10_000,
        threshold_millionths: 50_000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_symmetry_refusal_clone() {
    let a = SymmetryRefusal::ExceedsThreshold {
        axis_key: "core_count".to_string(),
        distance_millionths: 100_000,
        threshold_millionths: 50_000,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_obligation_graph_clone() {
    let a = simple_graph();
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// BTreeSet ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_domain_btreeset() {
    let set: BTreeSet<HardwareAxisDomain> = HardwareAxisDomain::ALL.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_obligation_status_btreeset() {
    let set: BTreeSet<ObligationStatus> = ObligationStatus::ALL.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

// ---------------------------------------------------------------------------
// Debug nonempty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_domain_debug() {
    for d in HardwareAxisDomain::ALL {
        assert!(!format!("{:?}", d).is_empty());
    }
}

#[test]
fn enrichment_obligation_status_debug() {
    for s in ObligationStatus::ALL {
        assert!(!format!("{:?}", s).is_empty());
    }
}

#[test]
fn enrichment_hardware_axis_debug() {
    assert!(!format!("{:?}", make_axis("x", HardwareAxisDomain::Io)).is_empty());
}

#[test]
fn enrichment_fingerprint_debug() {
    assert!(!format!("{:?}", make_fingerprint("fp-a", &[])).is_empty());
}

#[test]
fn enrichment_obligation_debug() {
    assert!(!format!("{:?}", Obligation::pending("fp", "q")).is_empty());
}

#[test]
fn enrichment_obligation_graph_debug() {
    assert!(!format!("{:?}", ObligationGraph::with_defaults()).is_empty());
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_domain_display_all_unique() {
    let displays: BTreeSet<String> = HardwareAxisDomain::ALL
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_obligation_status_display_all_unique() {
    let displays: BTreeSet<String> = ObligationStatus::ALL
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_symmetry_reason_display() {
    let r = SymmetryReason::WithinThreshold {
        max_distance_millionths: 10_000,
        threshold_millionths: 50_000,
    };
    assert!(r.to_string().contains("within threshold"));

    let r2 = SymmetryReason::ExpertAnnotation {
        note: "same gen".to_string(),
    };
    assert!(r2.to_string().contains("expert"));

    let r3 = SymmetryReason::EmpiricallyVerified {
        measurement_hash: ContentHash::compute(b"test"),
    };
    assert!(r3.to_string().contains("empirically"));
}

#[test]
fn enrichment_symmetry_refusal_display() {
    let r = SymmetryRefusal::ExceedsThreshold {
        axis_key: "core".to_string(),
        distance_millionths: 100_000,
        threshold_millionths: 50_000,
    };
    assert!(r.to_string().contains("core"));

    let mut missing = BTreeSet::new();
    missing.insert("x".to_string());
    let r2 = SymmetryRefusal::IncomparableAxes {
        missing_keys: missing,
    };
    assert!(r2.to_string().contains("missing"));

    let r3 = SymmetryRefusal::SimdMismatch {
        left_level: "avx2".to_string(),
        right_level: "sse4".to_string(),
    };
    assert!(r3.to_string().contains("SIMD"));

    let r4 = SymmetryRefusal::PlatformMismatch {
        detail: "different OS".to_string(),
    };
    assert!(r4.to_string().contains("platform"));
}

// ---------------------------------------------------------------------------
// as_str
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_domain_as_str() {
    for d in HardwareAxisDomain::ALL {
        assert_eq!(d.as_str(), d.to_string());
    }
}

#[test]
fn enrichment_obligation_status_as_str() {
    for s in ObligationStatus::ALL {
        assert_eq!(s.as_str(), s.to_string());
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert!(SCHEMA_VERSION.contains("hardware-parameter-manifold"));
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
    const {
        assert!(MAX_HARDWARE_AXES > 0);
        assert!(MAX_CLASS_SIZE > 0);
        assert!(DEFAULT_SIMILARITY_THRESHOLD > 0);
    }
}

// ---------------------------------------------------------------------------
// JSON field-name stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_json_fields() {
    let a = make_axis("core_count", HardwareAxisDomain::Microarch);
    let json = serde_json::to_string(&a).unwrap();
    for field in [
        "key",
        "domain",
        "min_millionths",
        "max_millionths",
        "required",
        "description",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_fingerprint_json_fields() {
    let fp = make_fingerprint("fp-a", &[("core_count", 500_000)]);
    let json = serde_json::to_string(&fp).unwrap();
    for field in ["id", "label", "values", "content_hash"] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_obligation_json_fields() {
    let o = Obligation::pending("fp-a", "q1");
    let json = serde_json::to_string(&o).unwrap();
    for field in [
        "fingerprint_id",
        "question_id",
        "status",
        "transport_source",
        "transport_class_id",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_obligation_status_json_fields() {
    for s in ObligationStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        assert!(!json.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hardware_axis_domain_serde_all() {
    for d in HardwareAxisDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: HardwareAxisDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn enrichment_obligation_status_serde_all() {
    for s in ObligationStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: ObligationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_hardware_axis_serde_roundtrip() {
    let a = make_axis("core_count", HardwareAxisDomain::Microarch);
    let json = serde_json::to_string(&a).unwrap();
    let back: HardwareAxis = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn enrichment_fingerprint_serde_roundtrip() {
    let fp = make_fingerprint("fp-a", &[("core_count", 500_000), ("mem_bw", 600_000)]);
    let json = serde_json::to_string(&fp).unwrap();
    let back: HardwareFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, back);
}

#[test]
fn enrichment_question_serde_roundtrip() {
    let q = make_question("q1", &["core_count", "mem_bw"]);
    let json = serde_json::to_string(&q).unwrap();
    let back: OptimizationQuestion = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
}

#[test]
fn enrichment_obligation_serde_roundtrip() {
    let mut o = Obligation::pending("fp-a", "q1");
    o.discharge_by_transport("fp-b", "class-1");
    let json = serde_json::to_string(&o).unwrap();
    let back: Obligation = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

#[test]
fn enrichment_symmetry_reason_serde_roundtrip() {
    let reasons = [
        SymmetryReason::WithinThreshold {
            max_distance_millionths: 10_000,
            threshold_millionths: 50_000,
        },
        SymmetryReason::ExpertAnnotation {
            note: "same gen".to_string(),
        },
        SymmetryReason::EmpiricallyVerified {
            measurement_hash: ContentHash::compute(b"test"),
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: SymmetryReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_symmetry_refusal_serde_roundtrip() {
    let r = SymmetryRefusal::ExceedsThreshold {
        axis_key: "core_count".to_string(),
        distance_millionths: 100_000,
        threshold_millionths: 50_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: SymmetryRefusal = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fingerprint_content_hash_determinism() {
    let fp1 = make_fingerprint("fp-a", &[("core_count", 500_000)]);
    let fp2 = make_fingerprint("fp-a", &[("core_count", 500_000)]);
    assert_eq!(fp1.content_hash, fp2.content_hash);
}

#[test]
fn enrichment_axis_content_hash_determinism() {
    let a1 = make_axis("core_count", HardwareAxisDomain::Microarch);
    let a2 = make_axis("core_count", HardwareAxisDomain::Microarch);
    assert_eq!(a1.content_hash(), a2.content_hash());
}

// ---------------------------------------------------------------------------
// HardwareAxis methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_axis_range_span() {
    let a = HardwareAxis::new(
        "x",
        HardwareAxisDomain::Microarch,
        100_000,
        900_000,
        false,
        "test",
    );
    assert_eq!(a.range_span(), 800_000);
}

#[test]
fn enrichment_axis_range_span_zero() {
    let a = HardwareAxis::new(
        "x",
        HardwareAxisDomain::Microarch,
        500_000,
        500_000,
        false,
        "test",
    );
    assert_eq!(a.range_span(), 0);
}

#[test]
fn enrichment_axis_normalize_mid() {
    let a = HardwareAxis::new(
        "x",
        HardwareAxisDomain::Microarch,
        0,
        1_000_000,
        false,
        "test",
    );
    assert_eq!(a.normalize(500_000), Some(500_000));
}

#[test]
fn enrichment_axis_normalize_min() {
    let a = HardwareAxis::new(
        "x",
        HardwareAxisDomain::Microarch,
        0,
        1_000_000,
        false,
        "test",
    );
    assert_eq!(a.normalize(0), Some(0));
}

#[test]
fn enrichment_axis_normalize_max() {
    let a = HardwareAxis::new(
        "x",
        HardwareAxisDomain::Microarch,
        0,
        1_000_000,
        false,
        "test",
    );
    assert_eq!(a.normalize(1_000_000), Some(1_000_000));
}

#[test]
fn enrichment_axis_normalize_clamps() {
    let a = HardwareAxis::new(
        "x",
        HardwareAxisDomain::Microarch,
        100_000,
        900_000,
        false,
        "test",
    );
    // Below min → clamps to min → normalized to 0
    assert_eq!(a.normalize(0), Some(0));
    // Above max → clamps to max → normalized to 1M
    assert_eq!(a.normalize(2_000_000), Some(1_000_000));
}

#[test]
fn enrichment_axis_normalize_zero_span() {
    let a = HardwareAxis::new(
        "x",
        HardwareAxisDomain::Microarch,
        500_000,
        500_000,
        false,
        "test",
    );
    assert_eq!(a.normalize(500_000), None);
}

#[test]
fn enrichment_axis_content_hash_varies_by_key() {
    let a = make_axis("core_count", HardwareAxisDomain::Microarch);
    let b = make_axis("mem_bw", HardwareAxisDomain::Microarch);
    assert_ne!(a.content_hash(), b.content_hash());
}

// ---------------------------------------------------------------------------
// HardwareFingerprint methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fingerprint_get() {
    let fp = make_fingerprint("fp-a", &[("core_count", 500_000), ("mem_bw", 600_000)]);
    assert_eq!(fp.get("core_count"), Some(500_000));
    assert_eq!(fp.get("mem_bw"), Some(600_000));
    assert_eq!(fp.get("nonexistent"), None);
}

#[test]
fn enrichment_fingerprint_axis_count() {
    let fp = make_fingerprint("fp-a", &[("core_count", 500_000), ("mem_bw", 600_000)]);
    assert_eq!(fp.axis_count(), 2);
}

#[test]
fn enrichment_fingerprint_content_hash_varies_by_id() {
    let a = make_fingerprint("fp-a", &[("core_count", 500_000)]);
    let b = make_fingerprint("fp-b", &[("core_count", 500_000)]);
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_fingerprint_content_hash_varies_by_values() {
    let a = make_fingerprint("fp-a", &[("core_count", 500_000)]);
    let b = make_fingerprint("fp-a", &[("core_count", 600_000)]);
    assert_ne!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// ObligationStatus methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obligation_status_is_resolved() {
    assert!(!ObligationStatus::Pending.is_resolved());
    assert!(ObligationStatus::DischargedDirect.is_resolved());
    assert!(ObligationStatus::DischargedByTransport.is_resolved());
    assert!(ObligationStatus::Infeasible.is_resolved());
    assert!(ObligationStatus::Waived.is_resolved());
}

#[test]
fn enrichment_obligation_status_is_discharged() {
    assert!(!ObligationStatus::Pending.is_discharged());
    assert!(ObligationStatus::DischargedDirect.is_discharged());
    assert!(ObligationStatus::DischargedByTransport.is_discharged());
    assert!(!ObligationStatus::Infeasible.is_discharged());
    assert!(!ObligationStatus::Waived.is_discharged());
}

// ---------------------------------------------------------------------------
// Obligation methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_obligation_pending() {
    let o = Obligation::pending("fp-a", "q1");
    assert_eq!(o.fingerprint_id, "fp-a");
    assert_eq!(o.question_id, "q1");
    assert_eq!(o.status, ObligationStatus::Pending);
    assert!(o.transport_source.is_none());
    assert!(o.transport_class_id.is_none());
}

#[test]
fn enrichment_obligation_discharge_direct() {
    let mut o = Obligation::pending("fp-a", "q1");
    o.discharge_direct();
    assert_eq!(o.status, ObligationStatus::DischargedDirect);
}

#[test]
fn enrichment_obligation_discharge_by_transport() {
    let mut o = Obligation::pending("fp-a", "q1");
    o.discharge_by_transport("fp-b", "class-1");
    assert_eq!(o.status, ObligationStatus::DischargedByTransport);
    assert_eq!(o.transport_source.as_deref(), Some("fp-b"));
    assert_eq!(o.transport_class_id.as_deref(), Some("class-1"));
}

#[test]
fn enrichment_obligation_mark_infeasible() {
    let mut o = Obligation::pending("fp-a", "q1");
    o.mark_infeasible();
    assert_eq!(o.status, ObligationStatus::Infeasible);
}

#[test]
fn enrichment_obligation_waive() {
    let mut o = Obligation::pending("fp-a", "q1");
    o.waive();
    assert_eq!(o.status, ObligationStatus::Waived);
}

// ---------------------------------------------------------------------------
// SymmetryReason tag
// ---------------------------------------------------------------------------

#[test]
fn enrichment_symmetry_reason_tags() {
    let r1 = SymmetryReason::WithinThreshold {
        max_distance_millionths: 0,
        threshold_millionths: 50_000,
    };
    assert_eq!(r1.tag(), "within_threshold");

    let r2 = SymmetryReason::ExpertAnnotation {
        note: "test".to_string(),
    };
    assert_eq!(r2.tag(), "expert_annotation");

    let r3 = SymmetryReason::EmpiricallyVerified {
        measurement_hash: ContentHash::compute(b"x"),
    };
    assert_eq!(r3.tag(), "empirically_verified");
}

// ---------------------------------------------------------------------------
// SymmetryRefusal tag
// ---------------------------------------------------------------------------

#[test]
fn enrichment_symmetry_refusal_tags() {
    let r1 = SymmetryRefusal::ExceedsThreshold {
        axis_key: "x".to_string(),
        distance_millionths: 100_000,
        threshold_millionths: 50_000,
    };
    assert_eq!(r1.tag(), "exceeds_threshold");

    let r2 = SymmetryRefusal::IncomparableAxes {
        missing_keys: BTreeSet::new(),
    };
    assert_eq!(r2.tag(), "incomparable_axes");

    let r3 = SymmetryRefusal::SimdMismatch {
        left_level: "a".to_string(),
        right_level: "b".to_string(),
    };
    assert_eq!(r3.tag(), "simd_mismatch");

    let r4 = SymmetryRefusal::PlatformMismatch {
        detail: "x".to_string(),
    };
    assert_eq!(r4.tag(), "platform_mismatch");
}

// ---------------------------------------------------------------------------
// SymmetryClass methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_symmetry_class_size() {
    let mut members = BTreeSet::new();
    members.insert("fp-a".to_string());
    members.insert("fp-b".to_string());
    let class = SymmetryClass::new(
        "c1",
        "fp-a",
        members,
        BTreeSet::new(),
        SymmetryReason::WithinThreshold {
            max_distance_millionths: 10_000,
            threshold_millionths: 50_000,
        },
    );
    assert_eq!(class.size(), 2);
    assert!(!class.is_trivial());
    assert!(class.contains("fp-a"));
    assert!(class.contains("fp-b"));
    assert!(!class.contains("fp-c"));
}

#[test]
fn enrichment_symmetry_class_trivial() {
    let mut members = BTreeSet::new();
    members.insert("fp-a".to_string());
    let class = SymmetryClass::new(
        "c1",
        "fp-a",
        members,
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation {
            note: "solo".to_string(),
        },
    );
    assert!(class.is_trivial());
}

// ---------------------------------------------------------------------------
// ObligationGraph methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_graph_new_empty() {
    let g = ObligationGraph::new(50_000);
    assert_eq!(g.obligation_count(), 0);
    assert_eq!(g.pending_count(), 0);
    assert_eq!(g.coverage_millionths(), 0);
}

#[test]
fn enrichment_graph_with_defaults() {
    let g = ObligationGraph::with_defaults();
    assert_eq!(g.similarity_threshold, DEFAULT_SIMILARITY_THRESHOLD);
}

#[test]
fn enrichment_graph_generate_obligations() {
    let mut g = simple_graph();
    g.generate_obligations();
    // 2 fingerprints × 1 question = 2 obligations
    assert_eq!(g.obligation_count(), 2);
    assert_eq!(g.pending_count(), 2);
}

#[test]
fn enrichment_graph_discharge_direct() {
    let mut g = simple_graph();
    g.generate_obligations();
    g.find_obligation_mut("fp-a", "q1")
        .unwrap()
        .discharge_direct();
    assert_eq!(g.pending_count(), 1);
    assert_eq!(g.discharged_count(), 1);
}

#[test]
fn enrichment_graph_reduce_by_symmetry() {
    let mut g = simple_graph();
    g.generate_obligations();

    // Create a symmetry class with both fingerprints
    let mut members = BTreeSet::new();
    members.insert("fp-a".to_string());
    members.insert("fp-b".to_string());
    let class = SymmetryClass::new(
        "c1",
        "fp-a",
        members,
        BTreeSet::new(),
        SymmetryReason::WithinThreshold {
            max_distance_millionths: 10_000,
            threshold_millionths: 50_000,
        },
    );
    g.add_symmetry_class(class);

    // Discharge rep's obligation
    g.find_obligation_mut("fp-a", "q1")
        .unwrap()
        .discharge_direct();
    g.reduce_by_symmetry();

    // fp-b's obligation should be discharged by transport
    let ob = g.find_obligation("fp-b", "q1").unwrap();
    assert_eq!(ob.status, ObligationStatus::DischargedByTransport);
    assert_eq!(ob.transport_source.as_deref(), Some("fp-a"));
    assert_eq!(g.transport_count(), 1);
}

#[test]
fn enrichment_graph_coverage_millionths() {
    let mut g = simple_graph();
    g.generate_obligations();
    assert_eq!(g.coverage_millionths(), 0);

    g.find_obligation_mut("fp-a", "q1")
        .unwrap()
        .discharge_direct();
    assert_eq!(g.coverage_millionths(), 500_000);

    g.find_obligation_mut("fp-b", "q1")
        .unwrap()
        .discharge_direct();
    assert_eq!(g.coverage_millionths(), 1_000_000);
}

#[test]
fn enrichment_graph_chebyshev_distance_same() {
    let g = simple_graph();
    let dist = g.chebyshev_distance("fp-a", "fp-a");
    assert_eq!(dist, Some(0));
}

#[test]
fn enrichment_graph_chebyshev_distance_close() {
    let g = simple_graph();
    let dist = g.chebyshev_distance("fp-a", "fp-b");
    assert!(dist.is_some());
    assert!(dist.unwrap() > 0);
}

#[test]
fn enrichment_graph_chebyshev_distance_missing() {
    let g = simple_graph();
    assert!(g.chebyshev_distance("fp-a", "nonexistent").is_none());
}

#[test]
fn enrichment_graph_check_symmetry_close() {
    let g = simple_graph();
    let result = g.check_symmetry("fp-a", "fp-b");
    assert!(result.is_ok());
}

#[test]
fn enrichment_graph_check_symmetry_missing_fp() {
    let g = simple_graph();
    let result = g.check_symmetry("fp-a", "nonexistent");
    assert!(result.is_err());
}

#[test]
fn enrichment_graph_check_symmetry_far_apart() {
    let mut g = ObligationGraph::new(1); // Very tight threshold
    g.add_axis(make_axis("core_count", HardwareAxisDomain::Microarch));
    g.add_fingerprint(make_fingerprint("fp-a", &[("core_count", 0)]));
    g.add_fingerprint(make_fingerprint("fp-b", &[("core_count", 1_000_000)]));
    let result = g.check_symmetry("fp-a", "fp-b");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// ObligationReport
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_empty_graph() {
    let g = ObligationGraph::with_defaults();
    let report = ObligationReport::from_graph(&g, SecurityEpoch::from_raw(1));
    assert_eq!(report.total_obligations, 0);
    assert!(report.is_complete());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_report_with_obligations() {
    let mut g = simple_graph();
    g.generate_obligations();
    let report = ObligationReport::from_graph(&g, SecurityEpoch::from_raw(1));
    assert_eq!(report.total_obligations, 2);
    assert_eq!(report.pending_obligations, 2);
    assert!(!report.is_complete());
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let g = simple_graph();
    let report = ObligationReport::from_graph(&g, SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&report).unwrap();
    let back: ObligationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_report_deterministic() {
    let g = simple_graph();
    let r1 = ObligationReport::from_graph(&g, SecurityEpoch::from_raw(1));
    let r2 = ObligationReport::from_graph(&g, SecurityEpoch::from_raw(1));
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// default_hardware_axes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_axes_nonempty() {
    let axes = default_hardware_axes();
    assert!(!axes.is_empty());
    assert!(axes.len() <= MAX_HARDWARE_AXES);
}

#[test]
fn enrichment_default_axes_unique_keys() {
    let axes = default_hardware_axes();
    let keys: BTreeSet<&str> = axes.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(keys.len(), axes.len());
}

#[test]
fn enrichment_default_axes_all_domains_covered() {
    let axes = default_hardware_axes();
    let domains: BTreeSet<HardwareAxisDomain> = axes.iter().map(|a| a.domain).collect();
    assert!(domains.len() >= 3); // At least Microarch, Memory, Platform
}

#[test]
fn enrichment_default_axes_valid_ranges() {
    for axis in default_hardware_axes() {
        assert!(axis.max_millionths >= axis.min_millionths);
    }
}
