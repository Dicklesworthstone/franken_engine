//! Integration tests for AARA resource certificates, effect summaries,
//! and symbolic potentials (RGC-625A).

use std::collections::BTreeMap;

use frankenengine_engine::aara_resource_certificate::{
    AbstentionPoint, AbstentionReason, AssumptionKind, BUNDLE_SCHEMA_VERSION,
    CERTIFICATE_SCHEMA_VERSION, COMPONENT, CertificateAssumption, CertificateBundle,
    CertificateInput, CertificateVerdict, EFFECT_SUMMARY_SCHEMA_VERSION, EffectEntry, EffectKind,
    EffectSummary, MAX_ABSTENTION_POINTS_PER_REGION, MAX_ASSUMPTIONS_PER_CERTIFICATE,
    MIN_CERTIFICATE_CONFIDENCE, POTENTIAL_SCHEMA_VERSION, ResourceBound, ResourceCertificate,
    ResourceDimension, SymbolicPotential,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn simple_effect_entry(kind: EffectKind, point: &str) -> EffectEntry {
    EffectEntry {
        kind,
        program_point: point.into(),
        worst_case_count_millionths: 1_000_000,
        is_exact: true,
    }
}

fn pure_effect_summary(region_id: &str) -> EffectSummary {
    EffectSummary::build(region_id, vec![], vec![])
}

fn simple_effect_summary(region_id: &str) -> EffectSummary {
    EffectSummary::build(
        region_id,
        vec![
            simple_effect_entry(EffectKind::Allocation, "fn:test:line:1"),
            simple_effect_entry(EffectKind::PropertyMutation, "fn:test:line:2"),
        ],
        vec![],
    )
}

fn simple_bound(dim: ResourceDimension) -> ResourceBound {
    ResourceBound {
        dimension: dim,
        upper_bound_millionths: 10_000_000,
        is_tight: true,
        confidence_millionths: 950_000,
    }
}

fn simple_potential(region_id: &str, dim: ResourceDimension) -> SymbolicPotential {
    let mut points = BTreeMap::new();
    points.insert("entry".into(), 1_000_000i64);
    points.insert("mid".into(), 500_000);
    points.insert("exit".into(), 100_000);
    SymbolicPotential::new(region_id, dim, 1_000_000, points)
}

fn simple_assumption(key: &str, kind: AssumptionKind) -> CertificateAssumption {
    CertificateAssumption {
        key: key.into(),
        kind,
        description: format!("Assumption: {key}"),
        is_critical: true,
    }
}

fn make_cert_input(
    cert_id: &str,
    region_id: &str,
    bounds: Vec<ResourceBound>,
    effects: EffectSummary,
    assumptions: Vec<CertificateAssumption>,
    abstentions: Vec<AbstentionPoint>,
    potentials: Vec<SymbolicPotential>,
) -> CertificateInput {
    CertificateInput {
        certificate_id: cert_id.into(),
        region_id: region_id.into(),
        epoch: test_epoch(),
        bounds,
        effect_summary: effects,
        assumptions,
        abstention_points: abstentions,
        potentials,
    }
}

fn simple_certificate(region_id: &str) -> ResourceCertificate {
    ResourceCertificate::new(make_cert_input(
        &format!("cert-{region_id}"),
        region_id,
        vec![simple_bound(ResourceDimension::Time)],
        simple_effect_summary(region_id),
        vec![simple_assumption("a1", AssumptionKind::NoEval)],
        vec![],
        vec![simple_potential(region_id, ResourceDimension::Time)],
    ))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert!(!CERTIFICATE_SCHEMA_VERSION.is_empty());
    assert!(!EFFECT_SUMMARY_SCHEMA_VERSION.is_empty());
    assert!(!POTENTIAL_SCHEMA_VERSION.is_empty());
    assert!(!BUNDLE_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_versions_unique() {
    let versions = [
        CERTIFICATE_SCHEMA_VERSION,
        EFFECT_SUMMARY_SCHEMA_VERSION,
        POTENTIAL_SCHEMA_VERSION,
        BUNDLE_SCHEMA_VERSION,
    ];
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            assert_ne!(versions[i], versions[j]);
        }
    }
}

#[test]
fn schema_versions_have_prefix() {
    assert!(CERTIFICATE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(EFFECT_SUMMARY_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(POTENTIAL_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(BUNDLE_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn threshold_constants_reasonable() {
    assert!(MAX_ASSUMPTIONS_PER_CERTIFICATE > 0);
    assert!(MAX_ABSTENTION_POINTS_PER_REGION > 0);
    assert!(MIN_CERTIFICATE_CONFIDENCE > 0);
    assert!(MIN_CERTIFICATE_CONFIDENCE <= 1_000_000);
}

// ---------------------------------------------------------------------------
// ResourceDimension
// ---------------------------------------------------------------------------

#[test]
fn resource_dimension_all_variants() {
    let all = ResourceDimension::ALL;
    assert!(all.len() >= 7);
    assert!(all.contains(&ResourceDimension::Time));
    assert!(all.contains(&ResourceDimension::HeapMemory));
    assert!(all.contains(&ResourceDimension::StackDepth));
    assert!(all.contains(&ResourceDimension::HostcallCount));
}

#[test]
fn resource_dimension_display_non_empty() {
    for dim in ResourceDimension::ALL {
        assert!(!format!("{dim}").is_empty());
    }
}

#[test]
fn resource_dimension_serde_round_trip() {
    for dim in ResourceDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let back: ResourceDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

// ---------------------------------------------------------------------------
// EffectKind
// ---------------------------------------------------------------------------

#[test]
fn effect_kind_display_all_variants() {
    let kinds = [
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
    for k in &kinds {
        assert!(!format!("{k}").is_empty());
    }
}

#[test]
fn effect_kind_dynamic_code_gen_forces_abstention() {
    assert!(EffectKind::DynamicCodeGen.forces_abstention());
    assert!(!EffectKind::Allocation.forces_abstention());
    assert!(!EffectKind::PropertyMutation.forces_abstention());
}

#[test]
fn effect_kind_serde_round_trip() {
    let kinds = [
        EffectKind::Allocation,
        EffectKind::DynamicCodeGen,
        EffectKind::Hostcall,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: EffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// AbstentionReason
// ---------------------------------------------------------------------------

#[test]
fn abstention_reason_display() {
    let reasons = [
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
    for r in &reasons {
        assert!(!format!("{r}").is_empty());
    }
}

#[test]
fn abstention_reason_serde_round_trip() {
    let r = AbstentionReason::UnboundedLoop;
    let json = serde_json::to_string(&r).unwrap();
    let back: AbstentionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// AssumptionKind
// ---------------------------------------------------------------------------

#[test]
fn assumption_kind_display() {
    let kinds = [
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
    for k in &kinds {
        assert!(!format!("{k}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// CertificateVerdict
// ---------------------------------------------------------------------------

#[test]
fn certificate_verdict_display() {
    for v in [
        CertificateVerdict::Certified,
        CertificateVerdict::Provisional,
        CertificateVerdict::Abstained,
        CertificateVerdict::Violated,
    ] {
        assert!(!format!("{v}").is_empty());
    }
}

#[test]
fn certificate_verdict_serde_round_trip() {
    for v in [
        CertificateVerdict::Certified,
        CertificateVerdict::Provisional,
        CertificateVerdict::Abstained,
        CertificateVerdict::Violated,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: CertificateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// EffectSummary
// ---------------------------------------------------------------------------

#[test]
fn effect_summary_pure_region() {
    let summary = pure_effect_summary("pure_fn");
    assert!(summary.is_pure());
    assert!(summary.is_complete);
    assert_eq!(summary.total_effect_count(), 0);
    assert!(!summary.has_dynamic_code_gen());
}

#[test]
fn effect_summary_with_effects() {
    let summary = simple_effect_summary("effectful_fn");
    assert!(!summary.is_pure());
    assert!(summary.is_complete);
    assert!(summary.total_effect_count() > 0);
}

#[test]
fn effect_summary_with_dynamic_code_gen() {
    let entries = vec![simple_effect_entry(
        EffectKind::DynamicCodeGen,
        "fn:evil:line:1",
    )];
    let summary = EffectSummary::build("evil_fn", entries, vec![]);
    assert!(summary.has_dynamic_code_gen());
}

#[test]
fn effect_summary_with_abstention() {
    let abstention = AbstentionPoint {
        program_point: "fn:loop:line:10".into(),
        reason: AbstentionReason::UnboundedLoop,
        detail: "while(true) loop".into(),
    };
    let summary = EffectSummary::build("loop_fn", vec![], vec![abstention]);
    assert!(!summary.is_complete);
    assert_eq!(summary.abstention_points.len(), 1);
}

#[test]
fn effect_summary_compose() {
    let s1 = simple_effect_summary("fn_a");
    let s2 = simple_effect_summary("fn_b");
    let composed = s1.compose(&s2);
    assert!(composed.total_effect_count() >= s1.total_effect_count());
}

#[test]
fn effect_summary_content_hash_deterministic() {
    let s1 = simple_effect_summary("hash_fn");
    let s2 = simple_effect_summary("hash_fn");
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn effect_summary_content_hash_differs() {
    let s1 = simple_effect_summary("fn_a");
    let s2 = simple_effect_summary("fn_b");
    assert_ne!(s1.content_hash, s2.content_hash);
}

#[test]
fn effect_summary_serde_round_trip() {
    let summary = simple_effect_summary("serde_fn");
    let json = serde_json::to_string(&summary).unwrap();
    let back: EffectSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// SymbolicPotential
// ---------------------------------------------------------------------------

#[test]
fn potential_new_valid() {
    let pot = simple_potential("valid_fn", ResourceDimension::Time);
    assert!(pot.is_valid);
    assert!(pot.min_potential_millionths >= 0);
    assert_eq!(pot.point_count(), 3);
}

#[test]
fn potential_with_negative() {
    let mut points = BTreeMap::new();
    points.insert("entry".into(), 1_000_000i64);
    points.insert("exit".into(), -500_000i64);
    let pot = SymbolicPotential::new("bad_fn", ResourceDimension::HeapMemory, 1_000_000, points);
    assert!(!pot.is_valid);
    assert!(pot.min_potential_millionths < 0);
}

#[test]
fn potential_terminal() {
    let mut points = BTreeMap::new();
    points.insert("a".into(), 500_000i64);
    points.insert("z".into(), 100_000i64);
    let pot = SymbolicPotential::new("term_fn", ResourceDimension::Time, 1_000_000, points);
    // Terminal is the last point in BTreeMap order ("z")
    assert_eq!(pot.terminal_potential(), 100_000);
}

#[test]
fn potential_empty_points_terminal_is_initial() {
    let pot = SymbolicPotential::new(
        "empty_fn",
        ResourceDimension::Time,
        500_000,
        BTreeMap::new(),
    );
    assert_eq!(pot.terminal_potential(), 500_000);
    assert_eq!(pot.point_count(), 0);
    assert!(pot.is_valid);
}

#[test]
fn potential_non_negative_fraction() {
    let mut points = BTreeMap::new();
    points.insert("a".into(), 100_000i64);
    points.insert("b".into(), 200_000i64);
    points.insert("c".into(), -100_000i64);
    let pot = SymbolicPotential::new("frac_fn", ResourceDimension::StackDepth, 1_000_000, points);
    // 2 out of 3 points are non-negative
    let frac = pot.non_negative_fraction_millionths();
    assert!(frac > 0);
    assert!(frac < 1_000_000);
}

#[test]
fn potential_content_hash_deterministic() {
    let p1 = simple_potential("hash_fn", ResourceDimension::Time);
    let p2 = simple_potential("hash_fn", ResourceDimension::Time);
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn potential_serde_round_trip() {
    let pot = simple_potential("serde_fn", ResourceDimension::HeapMemory);
    let json = serde_json::to_string(&pot).unwrap();
    let back: SymbolicPotential = serde_json::from_str(&json).unwrap();
    assert_eq!(pot, back);
}

// ---------------------------------------------------------------------------
// ResourceBound
// ---------------------------------------------------------------------------

#[test]
fn resource_bound_meets_confidence() {
    let bound = simple_bound(ResourceDimension::Time);
    assert!(bound.meets_confidence_threshold());
}

#[test]
fn resource_bound_below_confidence() {
    let bound = ResourceBound {
        dimension: ResourceDimension::Time,
        upper_bound_millionths: 10_000_000,
        is_tight: false,
        confidence_millionths: 500_000, // 50% — below MIN_CERTIFICATE_CONFIDENCE
    };
    assert!(!bound.meets_confidence_threshold());
}

#[test]
fn resource_bound_compose_same_dimension() {
    let b1 = simple_bound(ResourceDimension::HeapMemory);
    let b2 = ResourceBound {
        dimension: ResourceDimension::HeapMemory,
        upper_bound_millionths: 5_000_000,
        is_tight: true,
        confidence_millionths: 800_000,
    };
    let composed = b1.compose(&b2);
    assert!(composed.is_some());
    let c = composed.unwrap();
    assert_eq!(c.upper_bound_millionths, 15_000_000); // sum
    assert_eq!(c.confidence_millionths, 800_000); // min
}

#[test]
fn resource_bound_compose_different_dimension_none() {
    let b1 = simple_bound(ResourceDimension::Time);
    let b2 = simple_bound(ResourceDimension::HeapMemory);
    assert!(b1.compose(&b2).is_none());
}

#[test]
fn resource_bound_serde_round_trip() {
    let bound = simple_bound(ResourceDimension::GcPressure);
    let json = serde_json::to_string(&bound).unwrap();
    let back: ResourceBound = serde_json::from_str(&json).unwrap();
    assert_eq!(bound, back);
}

// ---------------------------------------------------------------------------
// ResourceCertificate
// ---------------------------------------------------------------------------

#[test]
fn certificate_certified_verdict() {
    let cert = simple_certificate("certified_fn");
    assert_eq!(cert.verdict, CertificateVerdict::Certified);
}

#[test]
fn certificate_dimension_coverage() {
    let cert = simple_certificate("dim_fn");
    let dims = cert.covered_dimensions();
    assert!(dims.contains(&ResourceDimension::Time));
    assert_eq!(cert.certified_dimension_count(), 1);
}

#[test]
fn certificate_bound_for_dimension() {
    let cert = simple_certificate("bound_fn");
    let bound = cert.bound_for(ResourceDimension::Time);
    assert!(bound.is_some());
    assert!(cert.bound_for(ResourceDimension::HeapMemory).is_none());
}

#[test]
fn certificate_all_potentials_valid() {
    let cert = simple_certificate("valid_fn");
    assert!(cert.all_potentials_valid());
}

#[test]
fn certificate_has_critical_assumptions() {
    let cert = simple_certificate("assumption_fn");
    assert!(cert.has_critical_assumptions());
}

#[test]
fn certificate_no_critical_assumptions() {
    let non_critical = CertificateAssumption {
        key: "a1".into(),
        kind: AssumptionKind::NoEval,
        description: "no eval".into(),
        is_critical: false,
    };
    let cert = ResourceCertificate::new(make_cert_input(
        "cert-nc",
        "nc_fn",
        vec![simple_bound(ResourceDimension::Time)],
        simple_effect_summary("nc_fn"),
        vec![non_critical],
        vec![],
        vec![simple_potential("nc_fn", ResourceDimension::Time)],
    ));
    assert!(!cert.has_critical_assumptions());
}

#[test]
fn certificate_with_abstention_gets_abstained_verdict() {
    let abstention = AbstentionPoint {
        program_point: "fn:loop:line:10".into(),
        reason: AbstentionReason::UnboundedLoop,
        detail: "while(true)".into(),
    };
    let cert = ResourceCertificate::new(make_cert_input(
        "cert-abs",
        "abs_fn",
        vec![simple_bound(ResourceDimension::Time)],
        simple_effect_summary("abs_fn"),
        vec![],
        vec![abstention],
        vec![simple_potential("abs_fn", ResourceDimension::Time)],
    ));
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);
}

#[test]
fn certificate_with_invalid_potential_gets_violated_verdict() {
    let mut points = BTreeMap::new();
    points.insert("entry".into(), 100_000i64);
    points.insert("exit".into(), -500_000i64);
    let bad_pot = SymbolicPotential::new("violated_fn", ResourceDimension::Time, 100_000, points);
    assert!(!bad_pot.is_valid);

    let cert = ResourceCertificate::new(make_cert_input(
        "cert-viol",
        "violated_fn",
        vec![simple_bound(ResourceDimension::Time)],
        simple_effect_summary("violated_fn"),
        vec![],
        vec![],
        vec![bad_pot],
    ));
    assert_eq!(cert.verdict, CertificateVerdict::Violated);
}

#[test]
fn certificate_with_low_confidence_gets_provisional_verdict() {
    let low_conf_bound = ResourceBound {
        dimension: ResourceDimension::Time,
        upper_bound_millionths: 10_000_000,
        is_tight: false,
        confidence_millionths: 500_000,
    };
    let cert = ResourceCertificate::new(make_cert_input(
        "cert-prov",
        "prov_fn",
        vec![low_conf_bound],
        simple_effect_summary("prov_fn"),
        vec![],
        vec![],
        vec![simple_potential("prov_fn", ResourceDimension::Time)],
    ));
    assert_eq!(cert.verdict, CertificateVerdict::Provisional);
}

#[test]
fn certificate_content_hash_deterministic() {
    let c1 = simple_certificate("hash_fn");
    let c2 = simple_certificate("hash_fn");
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn certificate_serde_round_trip() {
    let cert = simple_certificate("serde_fn");
    let json = serde_json::to_string(&cert).unwrap();
    let back: ResourceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// CertificateBundle
// ---------------------------------------------------------------------------

#[test]
fn bundle_empty() {
    let bundle = CertificateBundle::build("bundle-empty", test_epoch(), vec![]);
    assert_eq!(bundle.total_count(), 0);
    assert_eq!(bundle.certified_count, 0);
}

#[test]
fn bundle_with_certified() {
    let c1 = simple_certificate("fn_a");
    let c2 = simple_certificate("fn_b");
    let bundle = CertificateBundle::build("bundle-cert", test_epoch(), vec![c1, c2]);
    assert_eq!(bundle.total_count(), 2);
    assert_eq!(bundle.certified_count, 2);
    assert_eq!(bundle.certification_rate_millionths(), 1_000_000);
}

#[test]
fn bundle_passes_at_full_certification() {
    let c1 = simple_certificate("fn_a");
    let bundle = CertificateBundle::build("bundle-pass", test_epoch(), vec![c1]);
    assert!(bundle.passes(900_000));
}

#[test]
fn bundle_with_violation_fails() {
    let mut points = BTreeMap::new();
    points.insert("exit".into(), -1_000_000i64);
    let bad_pot = SymbolicPotential::new("viol_fn", ResourceDimension::Time, 100_000, points);
    let cert = ResourceCertificate::new(make_cert_input(
        "cert-viol",
        "viol_fn",
        vec![simple_bound(ResourceDimension::Time)],
        simple_effect_summary("viol_fn"),
        vec![],
        vec![],
        vec![bad_pot],
    ));
    assert_eq!(cert.verdict, CertificateVerdict::Violated);
    let bundle = CertificateBundle::build("bundle-viol", test_epoch(), vec![cert]);
    assert_eq!(bundle.violated_count, 1);
    assert!(!bundle.passes(0)); // Even at 0% threshold, violations fail
}

#[test]
fn bundle_mixed_certs() {
    let good = simple_certificate("good_fn");

    let abstention = AbstentionPoint {
        program_point: "fn:test:line:5".into(),
        reason: AbstentionReason::DynamicDispatch,
        detail: "dynamic dispatch".into(),
    };
    let abstained = ResourceCertificate::new(make_cert_input(
        "cert-abs",
        "abs_fn",
        vec![simple_bound(ResourceDimension::Time)],
        simple_effect_summary("abs_fn"),
        vec![],
        vec![abstention],
        vec![simple_potential("abs_fn", ResourceDimension::Time)],
    ));

    let bundle = CertificateBundle::build("bundle-mix", test_epoch(), vec![good, abstained]);
    assert_eq!(bundle.total_count(), 2);
    assert_eq!(bundle.certified_count, 1);
    assert_eq!(bundle.abstained_count, 1);
    assert_eq!(bundle.violated_count, 0);
    let rate = bundle.certification_rate_millionths();
    assert!(rate > 0);
    assert!(rate < 1_000_000);
}

#[test]
fn bundle_content_hash_deterministic() {
    let c1 = simple_certificate("fn_a");
    let b1 = CertificateBundle::build("bundle-det", test_epoch(), vec![c1.clone()]);
    let b2 = CertificateBundle::build("bundle-det", test_epoch(), vec![c1]);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn bundle_serde_round_trip() {
    let c1 = simple_certificate("fn_a");
    let bundle = CertificateBundle::build("bundle-serde", test_epoch(), vec![c1]);
    let json = serde_json::to_string(&bundle).unwrap();
    let back: CertificateBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ---------------------------------------------------------------------------
// End-to-end: build a certificate pipeline
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_certificate_pipeline() {
    // Build effect summaries for two functions
    let alloc_entries = vec![
        simple_effect_entry(EffectKind::Allocation, "fn:render:line:5"),
        simple_effect_entry(EffectKind::Allocation, "fn:render:line:10"),
        simple_effect_entry(EffectKind::PropertyMutation, "fn:render:line:15"),
    ];
    let render_effects = EffectSummary::build("render", alloc_entries, vec![]);
    assert!(!render_effects.is_pure());

    let compute_effects = pure_effect_summary("compute");
    assert!(compute_effects.is_pure());

    // Build potentials
    let mut render_points = BTreeMap::new();
    render_points.insert("entry".into(), 5_000_000i64);
    render_points.insert("alloc1".into(), 3_000_000);
    render_points.insert("alloc2".into(), 1_000_000);
    render_points.insert("exit".into(), 500_000);
    let render_pot = SymbolicPotential::new(
        "render",
        ResourceDimension::HeapMemory,
        5_000_000,
        render_points,
    );
    assert!(render_pot.is_valid);

    let compute_pot = simple_potential("compute", ResourceDimension::Time);
    assert!(compute_pot.is_valid);

    // Build certificates
    let render_cert = ResourceCertificate::new(make_cert_input(
        "cert-render",
        "render",
        vec![ResourceBound {
            dimension: ResourceDimension::HeapMemory,
            upper_bound_millionths: 4_500_000,
            is_tight: false,
            confidence_millionths: 950_000,
        }],
        render_effects,
        vec![simple_assumption(
            "stable-proto",
            AssumptionKind::StablePrototypes,
        )],
        vec![],
        vec![render_pot],
    ));
    assert_eq!(render_cert.verdict, CertificateVerdict::Certified);

    let compute_cert = ResourceCertificate::new(make_cert_input(
        "cert-compute",
        "compute",
        vec![simple_bound(ResourceDimension::Time)],
        compute_effects,
        vec![
            simple_assumption("bounded-iter", AssumptionKind::BoundedIteration),
            simple_assumption("no-eval", AssumptionKind::NoEval),
        ],
        vec![],
        vec![compute_pot],
    ));
    assert_eq!(compute_cert.verdict, CertificateVerdict::Certified);

    // Build bundle
    let bundle = CertificateBundle::build(
        "bundle-module",
        test_epoch(),
        vec![render_cert, compute_cert],
    );
    assert_eq!(bundle.total_count(), 2);
    assert_eq!(bundle.certified_count, 2);
    assert!(bundle.passes(900_000));
    assert_eq!(bundle.certification_rate_millionths(), 1_000_000);
}

#[test]
fn end_to_end_with_degradation() {
    // Function with eval forces abstention
    let eval_entry = simple_effect_entry(EffectKind::DynamicCodeGen, "fn:config:line:1");
    let eval_effects = EffectSummary::build("config_fn", vec![eval_entry], vec![]);
    assert!(eval_effects.has_dynamic_code_gen());

    let abstention = AbstentionPoint {
        program_point: "fn:config:line:1".into(),
        reason: AbstentionReason::DynamicCodeGen,
        detail: "eval() detected".into(),
    };

    let cert = ResourceCertificate::new(make_cert_input(
        "cert-eval",
        "config_fn",
        vec![simple_bound(ResourceDimension::Time)],
        eval_effects,
        vec![],
        vec![abstention],
        vec![simple_potential("config_fn", ResourceDimension::Time)],
    ));
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);

    let good_cert = simple_certificate("good_fn");
    let bundle = CertificateBundle::build("bundle-degraded", test_epoch(), vec![good_cert, cert]);
    assert_eq!(bundle.abstained_count, 1);
    assert_eq!(bundle.certified_count, 1);
    // 50% certification rate — may not pass a 90% threshold
    assert!(!bundle.passes(900_000));
}
