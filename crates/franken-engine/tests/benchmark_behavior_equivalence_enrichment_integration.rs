#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::benchmark_behavior_equivalence::{
    BEAD_ID, BehaviorEquivalenceClass, BehaviorEquivalenceObservation, BehaviorEquivalenceReport,
    BenchmarkParityVerdictRecord, COMPONENT, DivergenceOwnerRoute, EvidenceSurface, OwnerRoute,
    OwnerRouteHint, POLICY_ID, PublicationDisposition, SCHEMA_VERSION, build_record, build_report,
    publication_disposition_for, route_owner,
};
use frankenengine_engine::benchmark_evidence_bundle::ParityTarget;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn obs(
    workload_id: &str,
    surface: EvidenceSurface,
    output_equivalent: bool,
    feature_supported: bool,
    infra_ok: bool,
    noise_only: bool,
    owner_hint: OwnerRouteHint,
) -> BehaviorEquivalenceObservation {
    BehaviorEquivalenceObservation::new(workload_id, ParityTarget::NodeJs, surface, owner_hint)
        .with_output_equivalence(output_equivalent)
        .with_feature_supported(feature_supported)
        .with_infra_ok(infra_ok)
        .with_noise_only(noise_only)
        .with_detail("test-detail")
}

// =========================================================================
// A. BTreeSet ordering and dedup for all enums
// =========================================================================

#[test]
fn enrichment_evidence_surface_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(EvidenceSurface::LibraryOnly);
    set.insert(EvidenceSurface::ShippedPath);
    set.insert(EvidenceSurface::ShippedPath); // dup
    assert_eq!(set.len(), 2);
    let vals: Vec<_> = set.into_iter().collect();
    assert_eq!(vals[0], EvidenceSurface::ShippedPath);
    assert_eq!(vals[1], EvidenceSurface::LibraryOnly);
}

#[test]
fn enrichment_equivalence_class_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(BehaviorEquivalenceClass::ShippedPathDrift);
    set.insert(BehaviorEquivalenceClass::Equivalent);
    set.insert(BehaviorEquivalenceClass::InfraFailure);
    set.insert(BehaviorEquivalenceClass::BenchmarkNoise);
    set.insert(BehaviorEquivalenceClass::UnsupportedFeature);
    set.insert(BehaviorEquivalenceClass::SemanticMismatch);
    set.insert(BehaviorEquivalenceClass::Equivalent); // dup
    assert_eq!(set.len(), 6);
    let first = set.into_iter().next().unwrap();
    assert_eq!(first, BehaviorEquivalenceClass::Equivalent);
}

#[test]
fn enrichment_publication_disposition_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(PublicationDisposition::Blocked);
    set.insert(PublicationDisposition::PublicationEligible);
    set.insert(PublicationDisposition::NonPublicationEvidence);
    set.insert(PublicationDisposition::Blocked); // dup
    assert_eq!(set.len(), 3);
    let vals: Vec<_> = set.into_iter().collect();
    assert_eq!(vals[0], PublicationDisposition::PublicationEligible);
}

#[test]
fn enrichment_owner_route_hint_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(OwnerRouteHint::DocsContract);
    set.insert(OwnerRouteHint::RuntimeSemantics);
    set.insert(OwnerRouteHint::BenchmarkHarness);
    set.insert(OwnerRouteHint::ModuleInterop);
    set.insert(OwnerRouteHint::TypeScriptNormalization);
    set.insert(OwnerRouteHint::ShippedPathParity);
    set.insert(OwnerRouteHint::BenchmarkCorpus);
    set.insert(OwnerRouteHint::RuntimeSemantics); // dup
    assert_eq!(set.len(), 7);
}

// =========================================================================
// B. Hash consistency
// =========================================================================

#[test]
fn enrichment_evidence_surface_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    EvidenceSurface::ShippedPath.hash(&mut h1);
    EvidenceSurface::ShippedPath.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn enrichment_equivalence_class_hash_differs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    BehaviorEquivalenceClass::Equivalent.hash(&mut h1);
    BehaviorEquivalenceClass::InfraFailure.hash(&mut h2);
    assert_ne!(h1.finish(), h2.finish());
}

#[test]
fn enrichment_owner_route_hint_hash_differs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    OwnerRouteHint::RuntimeSemantics.hash(&mut h1);
    OwnerRouteHint::DocsContract.hash(&mut h2);
    assert_ne!(h1.finish(), h2.finish());
}

// =========================================================================
// C. Display distinctness
// =========================================================================

#[test]
fn enrichment_evidence_surface_display_distinct() {
    let displays: BTreeSet<String> = [EvidenceSurface::ShippedPath, EvidenceSurface::LibraryOnly]
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(displays.len(), 2);
}

#[test]
fn enrichment_equivalence_class_display_distinct() {
    let displays: BTreeSet<String> = [
        BehaviorEquivalenceClass::Equivalent,
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_publication_disposition_display_distinct() {
    let displays: BTreeSet<String> = [
        PublicationDisposition::PublicationEligible,
        PublicationDisposition::NonPublicationEvidence,
        PublicationDisposition::Blocked,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_owner_route_hint_display_distinct() {
    let displays: BTreeSet<String> = [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::TypeScriptNormalization,
        OwnerRouteHint::ShippedPathParity,
        OwnerRouteHint::BenchmarkHarness,
        OwnerRouteHint::BenchmarkCorpus,
        OwnerRouteHint::DocsContract,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 7);
}

// =========================================================================
// D. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", EvidenceSurface::ShippedPath).is_empty());
    assert!(!format!("{:?}", BehaviorEquivalenceClass::InfraFailure).is_empty());
    assert!(!format!("{:?}", PublicationDisposition::Blocked).is_empty());
    assert!(!format!("{:?}", OwnerRouteHint::RuntimeSemantics).is_empty());

    let observation = BehaviorEquivalenceObservation::new(
        "w1",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );
    assert!(!format!("{:?}", observation).is_empty());

    let record = build_record(&observation);
    assert!(!format!("{:?}", record).is_empty());

    let report = build_report("t", "d", "p", &[observation]);
    assert!(!format!("{:?}", report).is_empty());
}

// =========================================================================
// E. Clone independence
// =========================================================================

#[test]
fn enrichment_observation_clone_independence() {
    let original = BehaviorEquivalenceObservation::new(
        "w1",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_detail("original");
    let mut cloned = original.clone();
    cloned.detail = "mutated".into();
    assert_ne!(original.detail, cloned.detail);
    assert_eq!(original.workload_id, cloned.workload_id);
}

#[test]
fn enrichment_record_clone_independence() {
    let observation = BehaviorEquivalenceObservation::new(
        "w1",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );
    let record = build_record(&observation);
    let mut cloned = record.clone();
    cloned.detail = "mutated".into();
    assert_ne!(record.detail, cloned.detail);
    assert_eq!(record.record_hash, cloned.record_hash);
}

#[test]
fn enrichment_owner_route_clone_independence() {
    let route = route_owner(
        BehaviorEquivalenceClass::SemanticMismatch,
        OwnerRouteHint::ModuleInterop,
    )
    .unwrap();
    let mut cloned = route.clone();
    cloned.rationale = "changed".into();
    assert_ne!(route.rationale, cloned.rationale);
    assert_eq!(route.owner_bead_id, cloned.owner_bead_id);
}

// =========================================================================
// F. Individual struct serde roundtrips
// =========================================================================

#[test]
fn enrichment_owner_route_serde_roundtrip() {
    let route = route_owner(
        BehaviorEquivalenceClass::InfraFailure,
        OwnerRouteHint::RuntimeSemantics,
    )
    .unwrap();
    let json = serde_json::to_string(&route).unwrap();
    let back: OwnerRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, back);
}

#[test]
fn enrichment_divergence_owner_route_serde_roundtrip() {
    let dor = DivergenceOwnerRoute {
        owner_bead_id: BEAD_ID.to_string(),
        owner_hint: OwnerRouteHint::BenchmarkHarness,
        component: COMPONENT.to_string(),
        rationale: "test rationale".into(),
        workload_ids: vec!["w1".into(), "w2".into()],
        classifications: vec![
            BehaviorEquivalenceClass::InfraFailure,
            BehaviorEquivalenceClass::BenchmarkNoise,
        ],
    };
    let json = serde_json::to_string(&dor).unwrap();
    let back: DivergenceOwnerRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(dor, back);
}

#[test]
fn enrichment_verdict_record_serde_roundtrip() {
    let observation = BehaviorEquivalenceObservation::new(
        "w1",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false)
    .with_detail("serde test detail")
    .with_minimized_repro_command("frankenctl run --min");
    let record = build_record(&observation);
    let json = serde_json::to_string(&record).unwrap();
    let back: BenchmarkParityVerdictRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn enrichment_observation_all_fields_serde_roundtrip() {
    let observation = BehaviorEquivalenceObservation::new(
        "full_serde",
        ParityTarget::Bun,
        EvidenceSurface::LibraryOnly,
        OwnerRouteHint::DocsContract,
    )
    .with_output_equivalence(false)
    .with_feature_supported(false)
    .with_infra_ok(false)
    .with_noise_only(true)
    .with_detail("all flags bad")
    .with_minimized_repro_command("frankenctl repro");
    let json = serde_json::to_string(&observation).unwrap();
    let back: BehaviorEquivalenceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(observation, back);
}

// =========================================================================
// G. Report equality after serde roundtrip
// =========================================================================

#[test]
fn enrichment_report_serde_equality() {
    let observations = vec![
        obs(
            "w1",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "w2",
            EvidenceSurface::LibraryOnly,
            true,
            true,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
    ];
    let report = build_report("trace-eq", "dec-eq", POLICY_ID, &observations);
    let json = serde_json::to_string(&report).unwrap();
    let back: BehaviorEquivalenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// =========================================================================
// H. blocks_publication matches as_str distinction
// =========================================================================

#[test]
fn enrichment_blocks_publication_only_equivalent_false() {
    let classes = [
        BehaviorEquivalenceClass::Equivalent,
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    let non_blocking: Vec<_> = classes.iter().filter(|c| !c.blocks_publication()).collect();
    assert_eq!(non_blocking.len(), 1);
    assert_eq!(*non_blocking[0], BehaviorEquivalenceClass::Equivalent);
}

// =========================================================================
// I. publication_disposition_for all blocking classes
// =========================================================================

#[test]
fn enrichment_all_blocking_classes_blocked_regardless_of_surface() {
    let blocking = [
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for class in &blocking {
        assert_eq!(
            publication_disposition_for(*class, EvidenceSurface::ShippedPath),
            PublicationDisposition::Blocked
        );
        assert_eq!(
            publication_disposition_for(*class, EvidenceSurface::LibraryOnly),
            PublicationDisposition::Blocked
        );
    }
}

// =========================================================================
// J. route_owner for all non-equivalent classes
// =========================================================================

#[test]
fn enrichment_route_owner_all_non_equivalent_return_some() {
    let non_equivalent = [
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for class in &non_equivalent {
        let route = route_owner(*class, OwnerRouteHint::RuntimeSemantics);
        assert!(route.is_some(), "{class} should produce an owner route");
    }
}

// =========================================================================
// K. OwnerRouteHint component() matches as_str() for some hints
// =========================================================================

#[test]
fn enrichment_owner_hint_component_stable() {
    assert_eq!(
        OwnerRouteHint::TypeScriptNormalization.component(),
        "ts_normalization"
    );
    assert_eq!(
        OwnerRouteHint::ShippedPathParity.component(),
        "shipped_path_parity"
    );
    assert_eq!(
        OwnerRouteHint::DocsContract.component(),
        "docs_help_surface"
    );
}

// =========================================================================
// L. Record hash sensitivity to classification change
// =========================================================================

#[test]
fn enrichment_record_hash_sensitive_to_classification() {
    // Same workload but different classification paths produce different hashes.
    let obs_equiv = obs(
        "hash_class_test",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    let obs_infra = obs(
        "hash_class_test",
        EvidenceSurface::ShippedPath,
        true,
        true,
        false,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    let r1 = build_record(&obs_equiv);
    let r2 = build_record(&obs_infra);
    assert_ne!(r1.record_hash, r2.record_hash);
    assert_ne!(r1.classification, r2.classification);
}

// =========================================================================
// M. Report determinism across identical inputs
// =========================================================================

#[test]
fn enrichment_report_deterministic_replay() {
    let make = || {
        vec![
            obs(
                "w_z",
                EvidenceSurface::ShippedPath,
                false,
                true,
                true,
                false,
                OwnerRouteHint::RuntimeSemantics,
            ),
            obs(
                "w_a",
                EvidenceSurface::LibraryOnly,
                false,
                false,
                true,
                false,
                OwnerRouteHint::ModuleInterop,
            ),
        ]
    };
    let r1 = build_report("t", "d", POLICY_ID, &make());
    let r2 = build_report("t", "d", POLICY_ID, &make());
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2);
}

// =========================================================================
// N. Constants are correct
// =========================================================================

#[test]
fn enrichment_constants_cross_check() {
    assert!(SCHEMA_VERSION.contains("benchmark-behavior-equivalence"));
    assert_eq!(COMPONENT, "benchmark_behavior_equivalence");
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
}

// =========================================================================
// O. Observation builder defaults
// =========================================================================

#[test]
fn enrichment_observation_new_defaults() {
    let observation = BehaviorEquivalenceObservation::new(
        "test_defaults",
        ParityTarget::Deno,
        EvidenceSurface::LibraryOnly,
        OwnerRouteHint::BenchmarkCorpus,
    );
    assert!(observation.output_equivalent);
    assert!(observation.feature_supported);
    assert!(observation.infra_ok);
    assert!(!observation.noise_only);
    assert!(observation.detail.is_empty());
    assert!(observation.minimized_repro_command.is_none());
    assert_eq!(observation.workload_id, "test_defaults");
    assert_eq!(observation.baseline, ParityTarget::Deno);
    assert_eq!(observation.surface, EvidenceSurface::LibraryOnly);
    assert_eq!(observation.owner_hint, OwnerRouteHint::BenchmarkCorpus);
}

// =========================================================================
// P. Owner route aggregation workload_ids are deduplicated
// =========================================================================

#[test]
fn enrichment_owner_route_aggregation_dedup_workloads() {
    // Two observations with same workload ID, same classification, same owner.
    // They should both produce the same owner route key and the workload_ids
    // should be deduplicated (BTreeSet in aggregation code).
    let observations = vec![
        obs(
            "same_wk",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "same_wk",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
    ];
    let report = build_report("t", "d", "p", &observations);
    assert_eq!(report.owner_routes.len(), 1);
    // Workload IDs should be deduplicated.
    assert_eq!(report.owner_routes[0].workload_ids.len(), 1);
}

// =========================================================================
// Q. Report with all classification types
// =========================================================================

#[test]
fn enrichment_report_all_classification_types() {
    let observations = vec![
        obs(
            "equiv",
            EvidenceSurface::ShippedPath,
            true,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "infra",
            EvidenceSurface::ShippedPath,
            true,
            true,
            false,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "unsup",
            EvidenceSurface::ShippedPath,
            true,
            false,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "noise",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            true,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "drift",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "mismatch",
            EvidenceSurface::LibraryOnly,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    assert_eq!(report.records.len(), 6);

    let classes: BTreeSet<_> = report.records.iter().map(|r| r.classification).collect();
    assert_eq!(classes.len(), 6);

    // Only equiv has no owner route, so 5 records have routes.
    let with_routes = report
        .records
        .iter()
        .filter(|r| r.owner_route.is_some())
        .count();
    assert_eq!(with_routes, 5);
}
