//! Enrichment integration tests for `aara_resource_certificate`.
//!
//! Covers: ResourceDimension Display/serde, EffectKind Display/serde,
//! AbstentionReason Display/serde, AssumptionKind Display/serde,
//! CertificateVerdict Display/serde, EffectSummary lifecycle,
//! SymbolicPotential lifecycle, ResourceBound lifecycle,
//! ResourceCertificate lifecycle, CertificateBundle, and
//! deterministic content hashing.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::aara_resource_certificate::{
    AbstentionPoint, AbstentionReason, AssumptionKind, BUNDLE_SCHEMA_VERSION,
    CERTIFICATE_SCHEMA_VERSION, COMPONENT, CertificateAssumption, CertificateBundle,
    CertificateInput, CertificateVerdict, EFFECT_SUMMARY_SCHEMA_VERSION, EffectEntry, EffectKind,
    EffectSummary, MAX_ABSTENTION_POINTS_PER_REGION, MAX_ASSUMPTIONS_PER_CERTIFICATE,
    MIN_CERTIFICATE_CONFIDENCE, POTENTIAL_SCHEMA_VERSION, ResourceBound, ResourceCertificate,
    ResourceDimension, SymbolicPotential,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn simple_bound(dim: ResourceDimension, upper: i64, confidence: i64) -> ResourceBound {
    ResourceBound {
        dimension: dim,
        upper_bound_millionths: upper,
        is_tight: true,
        confidence_millionths: confidence,
    }
}

fn simple_potential(region_id: &str, dim: ResourceDimension) -> SymbolicPotential {
    let mut points = BTreeMap::new();
    points.insert("entry".into(), 1_000_000i64);
    points.insert("mid".into(), 500_000);
    points.insert("exit".into(), 100_000);
    SymbolicPotential::new(region_id, dim, 1_000_000, points)
}

fn simple_effect_entry(kind: EffectKind, point: &str) -> EffectEntry {
    EffectEntry {
        kind,
        program_point: point.into(),
        worst_case_count_millionths: 1_000_000,
        is_exact: true,
    }
}

fn simple_effect_summary(region_id: &str) -> EffectSummary {
    EffectSummary::build(
        region_id,
        vec![
            simple_effect_entry(EffectKind::Allocation, "fn:test:1"),
            simple_effect_entry(EffectKind::Hostcall, "fn:test:2"),
        ],
        vec![],
    )
}

fn make_cert(id: &str, region: &str) -> ResourceCertificate {
    let input = CertificateInput {
        certificate_id: id.into(),
        region_id: region.into(),
        epoch: ep(1),
        bounds: vec![simple_bound(ResourceDimension::Time, 10_000_000, 950_000)],
        effect_summary: simple_effect_summary(region),
        assumptions: vec![CertificateAssumption {
            key: "a1".into(),
            kind: AssumptionKind::NoEval,
            description: "no eval".into(),
            is_critical: true,
        }],
        abstention_points: vec![],
        potentials: vec![simple_potential(region, ResourceDimension::Time)],
    };
    ResourceCertificate::new(input)
}

// ===========================================================================
// ResourceDimension Display uniqueness
// ===========================================================================

#[test]
fn enrichment_resource_dimension_display_all_unique() {
    let displays: BTreeSet<String> = ResourceDimension::ALL
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(displays.len(), ResourceDimension::ALL.len());
}

#[test]
fn enrichment_resource_dimension_serde_roundtrip() {
    for dim in ResourceDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let back: ResourceDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

#[test]
fn enrichment_resource_dimension_all_count() {
    assert_eq!(ResourceDimension::ALL.len(), 7);
}

// ===========================================================================
// EffectKind Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_effect_kind_display_all_unique() {
    let all = [
        EffectKind::Allocation,
        EffectKind::PropertyMutation,
        EffectKind::GlobalRead,
        EffectKind::GlobalWrite,
        EffectKind::Hostcall,
        EffectKind::ModuleImport,
        EffectKind::ExceptionThrow,
        EffectKind::PrototypeTraversal,
        EffectKind::ClosureCapture,
        EffectKind::DynamicCodeGen,
    ];
    let displays: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_effect_kind_serde_roundtrip() {
    let all = [
        EffectKind::Allocation,
        EffectKind::PropertyMutation,
        EffectKind::GlobalRead,
        EffectKind::GlobalWrite,
        EffectKind::Hostcall,
        EffectKind::ModuleImport,
        EffectKind::ExceptionThrow,
        EffectKind::PrototypeTraversal,
        EffectKind::ClosureCapture,
        EffectKind::DynamicCodeGen,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: EffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_dynamic_code_gen_forces_abstention() {
    assert!(EffectKind::DynamicCodeGen.forces_abstention());
    assert!(!EffectKind::Allocation.forces_abstention());
    assert!(!EffectKind::Hostcall.forces_abstention());
}

// ===========================================================================
// AbstentionReason Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_abstention_reason_display_all_unique() {
    let all = [
        AbstentionReason::DynamicDispatch,
        AbstentionReason::DynamicCodeGen,
        AbstentionReason::UnboundedLoop,
        AbstentionReason::UnboundedRecursion,
        AbstentionReason::UnknownHostcall,
        AbstentionReason::PrototypeMutation,
        AbstentionReason::WithStatement,
        AbstentionReason::ProxyTrap,
        AbstentionReason::BudgetExhausted,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_abstention_reason_serde_roundtrip() {
    let all = [
        AbstentionReason::DynamicDispatch,
        AbstentionReason::DynamicCodeGen,
        AbstentionReason::UnboundedLoop,
        AbstentionReason::UnboundedRecursion,
        AbstentionReason::UnknownHostcall,
        AbstentionReason::PrototypeMutation,
        AbstentionReason::WithStatement,
        AbstentionReason::ProxyTrap,
        AbstentionReason::BudgetExhausted,
    ];
    for reason in &all {
        let json = serde_json::to_string(reason).unwrap();
        let back: AbstentionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ===========================================================================
// AssumptionKind Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_assumption_kind_display_all_unique() {
    let all = [
        AssumptionKind::BoundedIteration,
        AssumptionKind::NoEval,
        AssumptionKind::StaticDispatch,
        AssumptionKind::StablePrototypes,
        AssumptionKind::HostcallBoundsDeclared,
        AssumptionKind::NoWithStatement,
        AssumptionKind::NoProxyTraps,
        AssumptionKind::BoundedStackDepth,
        AssumptionKind::BoundedInputSize,
    ];
    let displays: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_assumption_kind_serde_roundtrip() {
    let all = [
        AssumptionKind::BoundedIteration,
        AssumptionKind::NoEval,
        AssumptionKind::StaticDispatch,
        AssumptionKind::StablePrototypes,
        AssumptionKind::HostcallBoundsDeclared,
        AssumptionKind::NoWithStatement,
        AssumptionKind::NoProxyTraps,
        AssumptionKind::BoundedStackDepth,
        AssumptionKind::BoundedInputSize,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: AssumptionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// CertificateVerdict Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_certificate_verdict_display_all_unique() {
    let all = [
        CertificateVerdict::Certified,
        CertificateVerdict::Provisional,
        CertificateVerdict::Abstained,
        CertificateVerdict::Violated,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_certificate_verdict_serde_roundtrip() {
    let all = [
        CertificateVerdict::Certified,
        CertificateVerdict::Provisional,
        CertificateVerdict::Abstained,
        CertificateVerdict::Violated,
    ];
    for verdict in &all {
        let json = serde_json::to_string(verdict).unwrap();
        let back: CertificateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*verdict, back);
    }
}

// ===========================================================================
// EffectSummary lifecycle
// ===========================================================================

#[test]
fn enrichment_effect_summary_pure_is_empty() {
    let summary = EffectSummary::build("pure-region", vec![], vec![]);
    assert!(summary.is_pure());
    assert!(summary.is_complete);
    assert_eq!(summary.total_effect_count(), 0);
    assert!(!summary.has_dynamic_code_gen());
}

#[test]
fn enrichment_effect_summary_total_effect_count() {
    let summary = simple_effect_summary("r1");
    assert_eq!(summary.total_effect_count(), 2_000_000);
}

#[test]
fn enrichment_effect_summary_has_dynamic_code_gen() {
    let summary = EffectSummary::build(
        "dyn-region",
        vec![simple_effect_entry(EffectKind::DynamicCodeGen, "eval:1")],
        vec![],
    );
    assert!(summary.has_dynamic_code_gen());
}

#[test]
fn enrichment_effect_summary_compose_merges_entries() {
    let s1 = EffectSummary::build(
        "r1",
        vec![simple_effect_entry(EffectKind::Allocation, "a:1")],
        vec![],
    );
    let s2 = EffectSummary::build(
        "r2",
        vec![simple_effect_entry(EffectKind::Hostcall, "b:1")],
        vec![],
    );
    let composed = s1.compose(&s2);
    assert_eq!(composed.entries.len(), 2);
    assert_eq!(composed.region_id, "r1+r2");
    assert!(composed.is_complete);
}

#[test]
fn enrichment_effect_summary_compose_with_abstentions() {
    let abs = AbstentionPoint {
        program_point: "x:0".into(),
        reason: AbstentionReason::DynamicDispatch,
        detail: "test".into(),
    };
    let s1 = EffectSummary::build("r1", vec![], vec![abs]);
    let s2 = EffectSummary::build("r2", vec![], vec![]);
    let composed = s1.compose(&s2);
    assert!(!composed.is_complete);
    assert_eq!(composed.abstention_points.len(), 1);
}

#[test]
fn enrichment_effect_summary_serde_roundtrip() {
    let summary = simple_effect_summary("serde-region");
    let json = serde_json::to_string(&summary).unwrap();
    let back: EffectSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_effect_summary_deterministic_hash() {
    let s1 = simple_effect_summary("deterministic");
    let s2 = simple_effect_summary("deterministic");
    assert_eq!(s1.content_hash, s2.content_hash);
}

// ===========================================================================
// SymbolicPotential lifecycle
// ===========================================================================

#[test]
fn enrichment_symbolic_potential_valid_non_negative() {
    let pot = simple_potential("valid-region", ResourceDimension::Time);
    assert!(pot.is_valid);
    assert!(pot.min_potential_millionths >= 0);
}

#[test]
fn enrichment_symbolic_potential_invalid_negative() {
    let mut points = BTreeMap::new();
    points.insert("entry".into(), 1_000_000i64);
    points.insert("violation".into(), -500_000i64);
    let pot = SymbolicPotential::new(
        "bad-region",
        ResourceDimension::HeapMemory,
        1_000_000,
        points,
    );
    assert!(!pot.is_valid);
    assert_eq!(pot.min_potential_millionths, -500_000);
}

#[test]
fn enrichment_symbolic_potential_terminal() {
    let pot = simple_potential("term-region", ResourceDimension::Time);
    // BTreeMap sorts keys alphabetically: "entry", "exit", "mid"
    // So the last value is "mid" = 500_000
    assert_eq!(pot.terminal_potential(), 500_000);
}

#[test]
fn enrichment_symbolic_potential_point_count() {
    let pot = simple_potential("count-region", ResourceDimension::Time);
    assert_eq!(pot.point_count(), 3);
}

#[test]
fn enrichment_symbolic_potential_non_negative_fraction() {
    let pot = simple_potential("frac-region", ResourceDimension::Time);
    assert_eq!(pot.non_negative_fraction_millionths(), 1_000_000);
}

#[test]
fn enrichment_symbolic_potential_deterministic_hash() {
    let p1 = simple_potential("det-region", ResourceDimension::Time);
    let p2 = simple_potential("det-region", ResourceDimension::Time);
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_symbolic_potential_serde_roundtrip() {
    let pot = simple_potential("serde-region", ResourceDimension::Time);
    let json = serde_json::to_string(&pot).unwrap();
    let back: SymbolicPotential = serde_json::from_str(&json).unwrap();
    assert_eq!(pot, back);
}

#[test]
fn enrichment_symbolic_potential_empty_points() {
    let pot = SymbolicPotential::new(
        "empty",
        ResourceDimension::GcPressure,
        500_000,
        BTreeMap::new(),
    );
    assert!(pot.is_valid);
    assert_eq!(pot.terminal_potential(), 500_000);
    assert_eq!(pot.point_count(), 0);
    assert_eq!(pot.non_negative_fraction_millionths(), 1_000_000);
}

// ===========================================================================
// ResourceBound lifecycle
// ===========================================================================

#[test]
fn enrichment_resource_bound_meets_confidence() {
    let bound = simple_bound(ResourceDimension::Time, 10_000_000, 950_000);
    assert!(bound.meets_confidence_threshold());
}

#[test]
fn enrichment_resource_bound_below_confidence() {
    let bound = simple_bound(ResourceDimension::Time, 10_000_000, 800_000);
    assert!(!bound.meets_confidence_threshold());
}

#[test]
fn enrichment_resource_bound_compose_same_dimension() {
    let b1 = simple_bound(ResourceDimension::HeapMemory, 5_000_000, 950_000);
    let b2 = simple_bound(ResourceDimension::HeapMemory, 3_000_000, 900_000);
    let composed = b1.compose(&b2).unwrap();
    assert_eq!(composed.upper_bound_millionths, 8_000_000);
    assert_eq!(composed.confidence_millionths, 900_000);
    assert!(composed.is_tight);
}

#[test]
fn enrichment_resource_bound_compose_different_dimension_none() {
    let b1 = simple_bound(ResourceDimension::Time, 5_000_000, 950_000);
    let b2 = simple_bound(ResourceDimension::HeapMemory, 3_000_000, 900_000);
    assert!(b1.compose(&b2).is_none());
}

#[test]
fn enrichment_resource_bound_serde_roundtrip() {
    let bound = simple_bound(ResourceDimension::StackDepth, 1_000_000, 999_000);
    let json = serde_json::to_string(&bound).unwrap();
    let back: ResourceBound = serde_json::from_str(&json).unwrap();
    assert_eq!(bound, back);
}

// ===========================================================================
// ResourceCertificate lifecycle
// ===========================================================================

#[test]
fn enrichment_certificate_certified_verdict_with_good_bounds() {
    let cert = make_cert("cert-good", "region-good");
    assert_eq!(cert.verdict, CertificateVerdict::Certified);
}

#[test]
fn enrichment_certificate_abstained_verdict_with_abstentions() {
    let input = CertificateInput {
        certificate_id: "cert-abstain".into(),
        region_id: "region-abstain".into(),
        epoch: ep(1),
        bounds: vec![],
        effect_summary: EffectSummary::build("region-abstain", vec![], vec![]),
        assumptions: vec![],
        abstention_points: vec![AbstentionPoint {
            program_point: "x:1".into(),
            reason: AbstentionReason::DynamicDispatch,
            detail: "test".into(),
        }],
        potentials: vec![],
    };
    let cert = ResourceCertificate::new(input);
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);
}

#[test]
fn enrichment_certificate_content_hash_deterministic() {
    let c1 = make_cert("cert-det", "region-det");
    let c2 = make_cert("cert-det", "region-det");
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn enrichment_certificate_certified_dimension_count() {
    let cert = make_cert("cert-dim", "region-dim");
    assert_eq!(cert.certified_dimension_count(), 1);
}

#[test]
fn enrichment_certificate_all_potentials_valid() {
    let cert = make_cert("cert-pot", "region-pot");
    assert!(cert.all_potentials_valid());
}

#[test]
fn enrichment_certificate_bound_for_existing_dimension() {
    let cert = make_cert("cert-bound", "region-bound");
    let bound = cert.bound_for(ResourceDimension::Time);
    assert!(bound.is_some());
    assert_eq!(bound.unwrap().upper_bound_millionths, 10_000_000);
}

#[test]
fn enrichment_certificate_bound_for_missing_dimension() {
    let cert = make_cert("cert-missing", "region-missing");
    assert!(cert.bound_for(ResourceDimension::GcPressure).is_none());
}

#[test]
fn enrichment_certificate_has_critical_assumptions() {
    let cert = make_cert("cert-crit", "region-crit");
    assert!(cert.has_critical_assumptions());
}

#[test]
fn enrichment_certificate_covered_dimensions() {
    let cert = make_cert("cert-cov", "region-cov");
    let dims = cert.covered_dimensions();
    assert!(dims.contains(&ResourceDimension::Time));
    assert_eq!(dims.len(), 1);
}

#[test]
fn enrichment_certificate_serde_roundtrip() {
    let cert = make_cert("cert-serde", "region-serde");
    let json = serde_json::to_string(&cert).unwrap();
    let back: ResourceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ===========================================================================
// CertificateBundle
// ===========================================================================

#[test]
fn enrichment_certificate_bundle_create_and_serde() {
    let cert1 = make_cert("cert-b1", "r1");
    let cert2 = make_cert("cert-b2", "r2");
    let bundle = CertificateBundle::build("bundle-1", ep(1), vec![cert1, cert2]);
    assert_eq!(bundle.certificates.len(), 2);

    let json = serde_json::to_string(&bundle).unwrap();
    let back: CertificateBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn enrichment_certificate_bundle_empty() {
    let bundle = CertificateBundle::build("empty-bundle", ep(1), vec![]);
    assert_eq!(bundle.certificates.len(), 0);
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert!(!CERTIFICATE_SCHEMA_VERSION.is_empty());
    assert!(!EFFECT_SUMMARY_SCHEMA_VERSION.is_empty());
    assert!(!POTENTIAL_SCHEMA_VERSION.is_empty());
    assert!(!BUNDLE_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_min_certificate_confidence_value() {
    assert_eq!(MIN_CERTIFICATE_CONFIDENCE, 900_000);
}

#[test]
fn enrichment_max_assumptions_per_certificate() {
    assert!(MAX_ASSUMPTIONS_PER_CERTIFICATE > 0);
}

#[test]
fn enrichment_max_abstention_points_per_region() {
    assert!(MAX_ABSTENTION_POINTS_PER_REGION > 0);
}
