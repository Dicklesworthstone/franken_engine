//! Integration tests for `hardware_parameter_manifold` module.
//!
//! Validates public API, serde contracts, determinism, symmetry detection,
//! obligation generation/reduction, and report generation.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hardware_parameter_manifold::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(500)
}

fn fp(id: &str, core_count: u64, mem_bw: u64) -> HardwareFingerprint {
    let mut values = BTreeMap::new();
    values.insert("core_count".to_string(), core_count);
    values.insert("mem_bandwidth_gbps".to_string(), mem_bw);
    HardwareFingerprint::new(id, format!("hw-{}", id), values)
}

fn question(id: &str) -> OptimizationQuestion {
    OptimizationQuestion::new(
        id,
        format!("Question {}", id),
        BTreeSet::from(["core_count".to_string()]),
    )
}

fn graph_with_axes() -> ObligationGraph {
    let mut g = ObligationGraph::with_defaults();
    for axis in default_hardware_axes() {
        g.add_axis(axis);
    }
    g
}

fn populated_graph() -> ObligationGraph {
    let mut g = graph_with_axes();
    g.add_fingerprint(fp("a", 8_000_000, 50_000_000));
    g.add_fingerprint(fp("b", 9_000_000, 53_000_000));
    g.add_fingerprint(fp("c", 64_000_000, 200_000_000));
    g.add_question(question("q1"));
    g.add_question(question("q2"));
    g
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("hardware"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "hardware_parameter_manifold");
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
fn max_hardware_axes_bounds() {
    assert!(MAX_HARDWARE_AXES > 0);
    assert!(MAX_HARDWARE_AXES <= 256);
}

#[test]
fn max_class_size_bounds() {
    assert!(MAX_CLASS_SIZE > 0);
}

#[test]
fn default_threshold_positive() {
    assert!(DEFAULT_SIMILARITY_THRESHOLD > 0);
    assert!(DEFAULT_SIMILARITY_THRESHOLD < 1_000_000);
}

// ---------------------------------------------------------------------------
// HardwareAxisDomain
// ---------------------------------------------------------------------------

#[test]
fn domain_all_length() {
    assert_eq!(HardwareAxisDomain::ALL.len(), 5);
}

#[test]
fn domain_names_unique() {
    let names: BTreeSet<&str> = HardwareAxisDomain::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(names.len(), HardwareAxisDomain::ALL.len());
}

#[test]
fn domain_display_matches_as_str() {
    for d in HardwareAxisDomain::ALL {
        assert_eq!(d.to_string(), d.as_str());
    }
}

#[test]
fn domain_serde_all() {
    for d in HardwareAxisDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: HardwareAxisDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ---------------------------------------------------------------------------
// HardwareAxis
// ---------------------------------------------------------------------------

#[test]
fn axis_range_span_positive() {
    let a = HardwareAxis::new("x", HardwareAxisDomain::Microarch, 100, 1000, true, "");
    assert_eq!(a.range_span(), 900);
}

#[test]
fn axis_normalize_boundaries() {
    let a = HardwareAxis::new("x", HardwareAxisDomain::Microarch, 0, 1_000_000, true, "");
    assert_eq!(a.normalize(0), Some(0));
    assert_eq!(a.normalize(1_000_000), Some(1_000_000));
    assert_eq!(a.normalize(500_000), Some(500_000));
}

#[test]
fn axis_normalize_clamps_below() {
    let a = HardwareAxis::new("x", HardwareAxisDomain::Memory, 100, 200, true, "");
    // Below min gets clamped to min → normalized to 0
    assert_eq!(a.normalize(0), Some(0));
}

#[test]
fn axis_normalize_clamps_above() {
    let a = HardwareAxis::new("x", HardwareAxisDomain::Memory, 100, 200, true, "");
    // Above max gets clamped to max → normalized to MILLION
    assert_eq!(a.normalize(999), Some(1_000_000));
}

#[test]
fn axis_normalize_zero_range_returns_none() {
    let a = HardwareAxis::new("x", HardwareAxisDomain::Io, 50, 50, false, "");
    assert!(a.normalize(50).is_none());
}

#[test]
fn axis_content_hash_deterministic() {
    let a1 = HardwareAxis::new("core", HardwareAxisDomain::Microarch, 1, 128, true, "cores");
    let a2 = HardwareAxis::new("core", HardwareAxisDomain::Microarch, 1, 128, true, "cores");
    assert_eq!(a1.content_hash(), a2.content_hash());
}

#[test]
fn axis_content_hash_differs_on_range() {
    let a1 = HardwareAxis::new("x", HardwareAxisDomain::Microarch, 1, 100, true, "");
    let a2 = HardwareAxis::new("x", HardwareAxisDomain::Microarch, 1, 200, true, "");
    assert_ne!(a1.content_hash(), a2.content_hash());
}

#[test]
fn axis_serde_roundtrip() {
    let a = HardwareAxis::new(
        "mem_bw",
        HardwareAxisDomain::Memory,
        10,
        1000,
        false,
        "bandwidth",
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: HardwareAxis = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ---------------------------------------------------------------------------
// HardwareFingerprint
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_creation() {
    let f = fp("fp1", 8_000_000, 50_000_000);
    assert_eq!(f.id, "fp1");
    assert_eq!(f.axis_count(), 2);
}

#[test]
fn fingerprint_get_existing() {
    let f = fp("fp1", 8_000_000, 50_000_000);
    assert_eq!(f.get("core_count"), Some(8_000_000));
    assert_eq!(f.get("mem_bandwidth_gbps"), Some(50_000_000));
}

#[test]
fn fingerprint_get_missing() {
    let f = fp("fp1", 8_000_000, 50_000_000);
    assert!(f.get("nonexistent").is_none());
}

#[test]
fn fingerprint_hash_deterministic() {
    let f1 = fp("fp1", 8_000_000, 50_000_000);
    let f2 = fp("fp1", 8_000_000, 50_000_000);
    assert_eq!(f1.content_hash, f2.content_hash);
}

#[test]
fn fingerprint_different_values_different_hash() {
    let f1 = fp("fp1", 8_000_000, 50_000_000);
    let f2 = fp("fp1", 16_000_000, 50_000_000);
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn fingerprint_serde_roundtrip() {
    let f = fp("test-fp", 32_000_000, 100_000_000);
    let json = serde_json::to_string(&f).unwrap();
    let back: HardwareFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// SymmetryReason
// ---------------------------------------------------------------------------

#[test]
fn symmetry_reason_tags_unique() {
    let reasons = vec![
        SymmetryReason::WithinThreshold {
            max_distance_millionths: 1000,
            threshold_millionths: 50_000,
        },
        SymmetryReason::ExpertAnnotation {
            note: "same gen".into(),
        },
        SymmetryReason::EmpiricallyVerified {
            measurement_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 3);
}

#[test]
fn symmetry_reason_display_contains_values() {
    let r = SymmetryReason::WithinThreshold {
        max_distance_millionths: 1234,
        threshold_millionths: 50_000,
    };
    let s = r.to_string();
    assert!(s.contains("1234"));
}

#[test]
fn symmetry_reason_serde_roundtrip() {
    let r = SymmetryReason::ExpertAnnotation {
        note: "test note".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: SymmetryReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// SymmetryRefusal
// ---------------------------------------------------------------------------

#[test]
fn symmetry_refusal_tags_unique() {
    let refusals = vec![
        SymmetryRefusal::ExceedsThreshold {
            axis_key: "x".into(),
            distance_millionths: 100_000,
            threshold_millionths: 50_000,
        },
        SymmetryRefusal::IncomparableAxes {
            missing_keys: BTreeSet::new(),
        },
        SymmetryRefusal::SimdMismatch {
            left_level: "avx2".into(),
            right_level: "neon".into(),
        },
        SymmetryRefusal::PlatformMismatch {
            detail: "os".into(),
        },
    ];
    let tags: BTreeSet<&str> = refusals.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 4);
}

#[test]
fn symmetry_refusal_display_content() {
    let r = SymmetryRefusal::ExceedsThreshold {
        axis_key: "core_count".into(),
        distance_millionths: 100_000,
        threshold_millionths: 50_000,
    };
    assert!(r.to_string().contains("core_count"));
}

#[test]
fn symmetry_refusal_serde_roundtrip() {
    let r = SymmetryRefusal::SimdMismatch {
        left_level: "avx512".into(),
        right_level: "neon".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: SymmetryRefusal = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// SymmetryClass
// ---------------------------------------------------------------------------

#[test]
fn symmetry_class_members() {
    let members = BTreeSet::from(["a".to_string(), "b".to_string(), "c".to_string()]);
    let class = SymmetryClass::new(
        "cls1",
        "a",
        members,
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation {
            note: "test".into(),
        },
    );
    assert_eq!(class.size(), 3);
    assert!(class.contains("a"));
    assert!(class.contains("b"));
    assert!(!class.contains("d"));
    assert!(!class.is_trivial());
}

#[test]
fn symmetry_class_trivial() {
    let members = BTreeSet::from(["only".to_string()]);
    let class = SymmetryClass::new(
        "cls",
        "only",
        members,
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation {
            note: "solo".into(),
        },
    );
    assert!(class.is_trivial());
    assert_eq!(class.size(), 1);
}

#[test]
fn symmetry_class_hash_deterministic() {
    let m = BTreeSet::from(["a".to_string(), "b".to_string()]);
    let c1 = SymmetryClass::new(
        "c",
        "a",
        m.clone(),
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation { note: "x".into() },
    );
    let c2 = SymmetryClass::new(
        "c",
        "a",
        m,
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation { note: "x".into() },
    );
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn symmetry_class_serde_roundtrip() {
    let m = BTreeSet::from(["a".to_string(), "b".to_string()]);
    let class = SymmetryClass::new(
        "cls",
        "a",
        m,
        BTreeSet::from(["core_count".to_string()]),
        SymmetryReason::WithinThreshold {
            max_distance_millionths: 5000,
            threshold_millionths: 50_000,
        },
    );
    let json = serde_json::to_string(&class).unwrap();
    let back: SymmetryClass = serde_json::from_str(&json).unwrap();
    assert_eq!(class, back);
}

// ---------------------------------------------------------------------------
// ObligationStatus
// ---------------------------------------------------------------------------

#[test]
fn status_all_length() {
    assert_eq!(ObligationStatus::ALL.len(), 5);
}

#[test]
fn status_names_unique() {
    let names: BTreeSet<&str> = ObligationStatus::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), ObligationStatus::ALL.len());
}

#[test]
fn status_pending_semantics() {
    assert!(!ObligationStatus::Pending.is_resolved());
    assert!(!ObligationStatus::Pending.is_discharged());
}

#[test]
fn status_discharged_semantics() {
    assert!(ObligationStatus::DischargedDirect.is_resolved());
    assert!(ObligationStatus::DischargedDirect.is_discharged());
    assert!(ObligationStatus::DischargedByTransport.is_resolved());
    assert!(ObligationStatus::DischargedByTransport.is_discharged());
}

#[test]
fn status_infeasible_semantics() {
    assert!(ObligationStatus::Infeasible.is_resolved());
    assert!(!ObligationStatus::Infeasible.is_discharged());
}

#[test]
fn status_waived_semantics() {
    assert!(ObligationStatus::Waived.is_resolved());
    assert!(!ObligationStatus::Waived.is_discharged());
}

#[test]
fn status_display_nonempty() {
    for s in ObligationStatus::ALL {
        assert!(!s.to_string().is_empty());
    }
}

#[test]
fn status_serde_all() {
    for s in ObligationStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: ObligationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// Obligation
// ---------------------------------------------------------------------------

#[test]
fn obligation_pending_creation() {
    let o = Obligation::pending("fp1", "q1");
    assert_eq!(o.fingerprint_id, "fp1");
    assert_eq!(o.question_id, "q1");
    assert_eq!(o.status, ObligationStatus::Pending);
    assert!(o.transport_source.is_none());
    assert!(o.transport_class_id.is_none());
}

#[test]
fn obligation_discharge_direct() {
    let mut o = Obligation::pending("fp1", "q1");
    o.discharge_direct();
    assert_eq!(o.status, ObligationStatus::DischargedDirect);
}

#[test]
fn obligation_discharge_by_transport() {
    let mut o = Obligation::pending("fp2", "q1");
    o.discharge_by_transport("fp1", "class1");
    assert_eq!(o.status, ObligationStatus::DischargedByTransport);
    assert_eq!(o.transport_source.as_deref(), Some("fp1"));
    assert_eq!(o.transport_class_id.as_deref(), Some("class1"));
}

#[test]
fn obligation_infeasible() {
    let mut o = Obligation::pending("fp1", "q1");
    o.mark_infeasible();
    assert_eq!(o.status, ObligationStatus::Infeasible);
}

#[test]
fn obligation_waive() {
    let mut o = Obligation::pending("fp1", "q1");
    o.waive();
    assert_eq!(o.status, ObligationStatus::Waived);
}

// ---------------------------------------------------------------------------
// ObligationGraph — basic
// ---------------------------------------------------------------------------

#[test]
fn graph_empty() {
    let g = ObligationGraph::with_defaults();
    assert_eq!(g.obligation_count(), 0);
    assert_eq!(g.pending_count(), 0);
    assert_eq!(g.discharged_count(), 0);
    assert_eq!(g.coverage_millionths(), 0);
    assert_eq!(g.transport_reduction_millionths(), 0);
}

#[test]
fn graph_generate_obligations_cross_product() {
    let mut g = populated_graph();
    g.generate_obligations();
    // 3 fingerprints × 2 questions = 6
    assert_eq!(g.obligation_count(), 6);
    assert_eq!(g.pending_count(), 6);
}

#[test]
fn graph_find_obligation() {
    let mut g = populated_graph();
    g.generate_obligations();
    assert!(g.find_obligation("a", "q1").is_some());
    assert!(g.find_obligation("c", "q2").is_some());
    assert!(g.find_obligation("a", "q_nonexistent").is_none());
}

#[test]
fn graph_discharge_reduces_pending() {
    let mut g = populated_graph();
    g.generate_obligations();
    g.find_obligation_mut("a", "q1").unwrap().discharge_direct();
    assert_eq!(g.pending_count(), 5);
    assert_eq!(g.discharged_count(), 1);
}

#[test]
fn graph_full_coverage() {
    let mut g = populated_graph();
    g.generate_obligations();
    for o in &mut g.obligations {
        o.discharge_direct();
    }
    assert_eq!(g.coverage_millionths(), 1_000_000);
    assert_eq!(g.pending_count(), 0);
}

// ---------------------------------------------------------------------------
// ObligationGraph — symmetry reduction
// ---------------------------------------------------------------------------

#[test]
fn graph_symmetry_reduces_obligations() {
    let mut g = populated_graph();
    let members = BTreeSet::from(["a".to_string(), "b".to_string()]);
    g.add_symmetry_class(SymmetryClass::new(
        "cls_ab",
        "a",
        members,
        BTreeSet::new(),
        SymmetryReason::WithinThreshold {
            max_distance_millionths: 3000,
            threshold_millionths: 50_000,
        },
    ));
    g.generate_obligations();
    // Discharge a's obligations directly
    g.find_obligation_mut("a", "q1").unwrap().discharge_direct();
    g.find_obligation_mut("a", "q2").unwrap().discharge_direct();
    // Reduce
    g.reduce_by_symmetry();
    // b's obligations should be transported
    assert_eq!(
        g.find_obligation("b", "q1").unwrap().status,
        ObligationStatus::DischargedByTransport
    );
    assert_eq!(
        g.find_obligation("b", "q2").unwrap().status,
        ObligationStatus::DischargedByTransport
    );
    // c should still be pending
    assert_eq!(
        g.find_obligation("c", "q1").unwrap().status,
        ObligationStatus::Pending
    );
}

#[test]
fn graph_symmetry_only_transports_pending() {
    let mut g = populated_graph();
    let members = BTreeSet::from(["a".to_string(), "b".to_string()]);
    g.add_symmetry_class(SymmetryClass::new(
        "cls",
        "a",
        members,
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation {
            note: "test".into(),
        },
    ));
    g.generate_obligations();
    // Mark b/q1 as infeasible before reduction
    g.find_obligation_mut("b", "q1").unwrap().mark_infeasible();
    g.find_obligation_mut("a", "q1").unwrap().discharge_direct();
    g.find_obligation_mut("a", "q2").unwrap().discharge_direct();
    g.reduce_by_symmetry();
    // b/q1 was infeasible → should stay infeasible (not overwritten)
    assert_eq!(
        g.find_obligation("b", "q1").unwrap().status,
        ObligationStatus::Infeasible
    );
    // b/q2 was pending → should be transported
    assert_eq!(
        g.find_obligation("b", "q2").unwrap().status,
        ObligationStatus::DischargedByTransport
    );
}

#[test]
fn graph_transport_reduction_ratio() {
    let mut g = populated_graph();
    let members = BTreeSet::from(["a".to_string(), "b".to_string()]);
    g.add_symmetry_class(SymmetryClass::new(
        "cls",
        "a",
        members,
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation { note: "t".into() },
    ));
    g.generate_obligations();
    g.find_obligation_mut("a", "q1").unwrap().discharge_direct();
    g.find_obligation_mut("a", "q2").unwrap().discharge_direct();
    g.reduce_by_symmetry();
    // 2 direct + 2 transport = 4 discharged. Transport = 2/4 = 500_000
    assert_eq!(g.transport_reduction_millionths(), 500_000);
}

// ---------------------------------------------------------------------------
// ObligationGraph — distance & symmetry check
// ---------------------------------------------------------------------------

#[test]
fn graph_chebyshev_similar_configs() {
    let g = populated_graph();
    let dist = g.chebyshev_distance("a", "b").unwrap();
    // a and b have similar values — distance should be small
    assert!(dist < DEFAULT_SIMILARITY_THRESHOLD);
}

#[test]
fn graph_chebyshev_different_configs() {
    let g = populated_graph();
    let dist = g.chebyshev_distance("a", "c").unwrap();
    assert!(dist > DEFAULT_SIMILARITY_THRESHOLD);
}

#[test]
fn graph_chebyshev_self_is_zero() {
    let g = populated_graph();
    assert_eq!(g.chebyshev_distance("a", "a"), Some(0));
}

#[test]
fn graph_chebyshev_unknown_returns_none() {
    let g = populated_graph();
    assert!(g.chebyshev_distance("a", "unknown").is_none());
}

#[test]
fn graph_check_symmetry_similar() {
    let g = populated_graph();
    assert!(g.check_symmetry("a", "b").is_ok());
}

#[test]
fn graph_check_symmetry_different() {
    let g = populated_graph();
    let result = g.check_symmetry("a", "c");
    assert!(result.is_err());
}

#[test]
fn graph_check_symmetry_unknown_fp() {
    let g = populated_graph();
    let result = g.check_symmetry("a", "nonexistent");
    assert!(result.is_err());
}

#[test]
fn graph_serde_roundtrip() {
    let mut g = populated_graph();
    g.generate_obligations();
    let json = serde_json::to_string(&g).unwrap();
    let back: ObligationGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

// ---------------------------------------------------------------------------
// ObligationReport
// ---------------------------------------------------------------------------

#[test]
fn report_empty() {
    let g = ObligationGraph::with_defaults();
    let r = ObligationReport::from_graph(&g, epoch());
    assert_eq!(r.total_obligations, 0);
    assert_eq!(r.pending_obligations, 0);
    assert!(r.is_complete());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_partial_coverage() {
    let mut g = populated_graph();
    g.generate_obligations();
    g.find_obligation_mut("a", "q1").unwrap().discharge_direct();
    let r = ObligationReport::from_graph(&g, epoch());
    assert_eq!(r.total_obligations, 6);
    assert_eq!(r.pending_obligations, 5);
    assert_eq!(r.direct_discharges, 1);
    assert!(!r.is_complete());
}

#[test]
fn report_with_transport() {
    let mut g = populated_graph();
    let m = BTreeSet::from(["a".to_string(), "b".to_string()]);
    g.add_symmetry_class(SymmetryClass::new(
        "cls",
        "a",
        m,
        BTreeSet::new(),
        SymmetryReason::ExpertAnnotation { note: "t".into() },
    ));
    g.generate_obligations();
    g.find_obligation_mut("a", "q1").unwrap().discharge_direct();
    g.find_obligation_mut("a", "q2").unwrap().discharge_direct();
    g.reduce_by_symmetry();
    let r = ObligationReport::from_graph(&g, epoch());
    assert_eq!(r.direct_discharges, 2);
    assert_eq!(r.transport_discharges, 2);
    assert_eq!(r.symmetry_class_count, 1);
    assert_eq!(r.nontrivial_class_count, 1);
}

#[test]
fn report_infeasible_and_waived() {
    let mut g = populated_graph();
    g.generate_obligations();
    g.find_obligation_mut("a", "q1").unwrap().mark_infeasible();
    g.find_obligation_mut("b", "q2").unwrap().waive();
    let r = ObligationReport::from_graph(&g, epoch());
    assert_eq!(r.infeasible_count, 1);
    assert_eq!(r.waived_count, 1);
    assert_eq!(r.pending_obligations, 4);
}

#[test]
fn report_hash_deterministic() {
    let g = populated_graph();
    let r1 = ObligationReport::from_graph(&g, epoch());
    let r2 = ObligationReport::from_graph(&g, epoch());
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_different_state_different_hash() {
    let mut g1 = populated_graph();
    g1.generate_obligations();
    let r1 = ObligationReport::from_graph(&g1, epoch());

    let mut g2 = populated_graph();
    g2.generate_obligations();
    g2.find_obligation_mut("a", "q1")
        .unwrap()
        .discharge_direct();
    let r2 = ObligationReport::from_graph(&g2, epoch());

    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let mut g = populated_graph();
    g.generate_obligations();
    g.find_obligation_mut("a", "q1").unwrap().discharge_direct();
    let r = ObligationReport::from_graph(&g, epoch());
    let json = serde_json::to_string(&r).unwrap();
    let back: ObligationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// default_hardware_axes
// ---------------------------------------------------------------------------

#[test]
fn default_axes_count() {
    let axes = default_hardware_axes();
    assert_eq!(axes.len(), 12);
}

#[test]
fn default_axes_keys_unique() {
    let axes = default_hardware_axes();
    let keys: BTreeSet<&str> = axes.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(keys.len(), axes.len());
}

#[test]
fn default_axes_all_domains_represented() {
    let axes = default_hardware_axes();
    let domains: BTreeSet<HardwareAxisDomain> = axes.iter().map(|a| a.domain).collect();
    assert_eq!(domains.len(), HardwareAxisDomain::ALL.len());
}

#[test]
fn default_axes_valid_ranges() {
    for axis in default_hardware_axes() {
        assert!(
            axis.max_millionths >= axis.min_millionths,
            "axis {} has inverted range",
            axis.key
        );
    }
}

#[test]
fn default_axes_required_count() {
    let axes = default_hardware_axes();
    let required = axes.iter().filter(|a| a.required).count();
    assert!(required >= 2);
}

#[test]
fn default_axes_normalizable() {
    for axis in default_hardware_axes() {
        // Mid-range value should normalize to something
        let mid = axis.min_millionths.saturating_add(axis.max_millionths) / 2;
        if axis.range_span() > 0 {
            assert!(
                axis.normalize(mid).is_some(),
                "axis {} not normalizable",
                axis.key
            );
        }
    }
}
