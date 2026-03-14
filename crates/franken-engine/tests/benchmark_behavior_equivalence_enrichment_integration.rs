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

// ===== PearlTower enrichment =====

// =========================================================================
// R. Serde roundtrip for key types
// =========================================================================

#[test]
fn enrichment_behavior_equivalence_class_serde_roundtrip_all_variants() {
    let variants = [
        BehaviorEquivalenceClass::Equivalent,
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: BehaviorEquivalenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back, "serde roundtrip failed for {variant:?}");
    }
}

#[test]
fn enrichment_evidence_surface_serde_roundtrip_all_variants() {
    for variant in [EvidenceSurface::ShippedPath, EvidenceSurface::LibraryOnly] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: EvidenceSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn enrichment_publication_disposition_serde_roundtrip_all_variants() {
    let variants = [
        PublicationDisposition::PublicationEligible,
        PublicationDisposition::NonPublicationEvidence,
        PublicationDisposition::Blocked,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: PublicationDisposition = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn enrichment_owner_route_hint_serde_roundtrip_all_variants() {
    let variants = [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::TypeScriptNormalization,
        OwnerRouteHint::ShippedPathParity,
        OwnerRouteHint::BenchmarkHarness,
        OwnerRouteHint::BenchmarkCorpus,
        OwnerRouteHint::DocsContract,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: OwnerRouteHint = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn enrichment_observation_with_repro_command_serde_roundtrip() {
    let observation = BehaviorEquivalenceObservation::new(
        "repro_roundtrip",
        ParityTarget::V8Isolate,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::BenchmarkHarness,
    )
    .with_output_equivalence(false)
    .with_minimized_repro_command("frankenctl bench --repro repro_roundtrip");
    let json = serde_json::to_string(&observation).unwrap();
    let back: BehaviorEquivalenceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(observation, back);
    assert_eq!(
        back.minimized_repro_command.as_deref(),
        Some("frankenctl bench --repro repro_roundtrip")
    );
}

// =========================================================================
// S. Edge cases (empty inputs, boundary values, single-element)
// =========================================================================

#[test]
fn enrichment_empty_observations_report_has_no_blockers() {
    let report = build_report("trace-empty", "dec-empty", POLICY_ID, &[]);
    assert!(report.records.is_empty());
    assert!(report.owner_routes.is_empty());
    assert!(!report.has_publication_blockers());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
}

#[test]
fn enrichment_single_equivalent_observation_report() {
    let single = vec![BehaviorEquivalenceObservation::new(
        "solo",
        ParityTarget::Bun,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::BenchmarkCorpus,
    )];
    let report = build_report("t-solo", "d-solo", POLICY_ID, &single);
    assert_eq!(report.records.len(), 1);
    assert!(report.owner_routes.is_empty());
    assert!(!report.has_publication_blockers());
    assert_eq!(
        report.records[0].classification,
        BehaviorEquivalenceClass::Equivalent
    );
    assert_eq!(
        report.records[0].publication_disposition,
        PublicationDisposition::PublicationEligible
    );
}

#[test]
fn enrichment_single_failing_observation_report_has_one_route() {
    let single = vec![
        BehaviorEquivalenceObservation::new(
            "solo_fail",
            ParityTarget::Deno,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        )
        .with_output_equivalence(false),
    ];
    let report = build_report("t-solo-fail", "d-solo-fail", POLICY_ID, &single);
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.owner_routes.len(), 1);
    assert!(report.has_publication_blockers());
}

#[test]
fn enrichment_empty_detail_string_allowed_in_observation() {
    let observation = BehaviorEquivalenceObservation::new(
        "empty_detail",
        ParityTarget::NodeJs,
        EvidenceSurface::LibraryOnly,
        OwnerRouteHint::ModuleInterop,
    );
    assert!(observation.detail.is_empty());
    let record = build_record(&observation);
    assert!(record.detail.is_empty());
}

#[test]
fn enrichment_boundary_workload_id_whitespace_preserved() {
    // Workload IDs with surrounding whitespace must be passed through unchanged.
    let wid = "  workload with spaces  ";
    let observation = BehaviorEquivalenceObservation::new(
        wid,
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::BenchmarkCorpus,
    );
    assert_eq!(observation.workload_id, wid);
    let record = build_record(&observation);
    assert_eq!(record.workload_id, wid);
}

// =========================================================================
// T. Deterministic output verification (same inputs → same output)
// =========================================================================

#[test]
fn enrichment_build_record_hash_deterministic_across_calls() {
    let observation = BehaviorEquivalenceObservation::new(
        "det_hash",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false)
    .with_detail("determinism check");
    let r1 = build_record(&observation);
    let r2 = build_record(&observation);
    let r3 = build_record(&observation);
    assert_eq!(r1.record_hash, r2.record_hash);
    assert_eq!(r2.record_hash, r3.record_hash);
}

#[test]
fn enrichment_build_report_jsonl_deterministic_across_calls() {
    let observations = vec![
        obs(
            "alpha",
            EvidenceSurface::ShippedPath,
            true,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "beta",
            EvidenceSurface::LibraryOnly,
            false,
            true,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
    ];
    let r1 = build_report("trace-det", "dec-det", POLICY_ID, &observations);
    let r2 = build_report("trace-det", "dec-det", POLICY_ID, &observations);
    assert_eq!(
        r1.benchmark_parity_verdict_jsonl().unwrap(),
        r2.benchmark_parity_verdict_jsonl().unwrap()
    );
    assert_eq!(
        r1.divergence_owner_route_json().unwrap(),
        r2.divergence_owner_route_json().unwrap()
    );
}

#[test]
fn enrichment_record_hash_differs_when_workload_id_differs() {
    let make_obs = |wid: &str| {
        BehaviorEquivalenceObservation::new(
            wid,
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        )
    };
    let r1 = build_record(&make_obs("wk_a"));
    let r2 = build_record(&make_obs("wk_b"));
    assert_ne!(r1.record_hash, r2.record_hash);
}

#[test]
fn enrichment_record_hash_differs_when_surface_differs() {
    let make_obs = |surface| {
        BehaviorEquivalenceObservation::new(
            "same_wk",
            ParityTarget::NodeJs,
            surface,
            OwnerRouteHint::RuntimeSemantics,
        )
    };
    let r1 = build_record(&make_obs(EvidenceSurface::ShippedPath));
    let r2 = build_record(&make_obs(EvidenceSurface::LibraryOnly));
    assert_ne!(r1.record_hash, r2.record_hash);
}

#[test]
fn enrichment_record_hash_differs_when_repro_command_present_vs_absent() {
    let base = BehaviorEquivalenceObservation::new(
        "repro_hash_check",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::BenchmarkHarness,
    )
    .with_output_equivalence(false);
    let with_repro = base.clone().with_minimized_repro_command("cmd repro");
    let r1 = build_record(&base);
    let r2 = build_record(&with_repro);
    assert_ne!(r1.record_hash, r2.record_hash);
}

// =========================================================================
// U. Clone/Debug derive verification
// =========================================================================

#[test]
fn enrichment_clone_derive_all_enum_variants() {
    let s1 = EvidenceSurface::ShippedPath;
    let s2 = s1;
    assert_eq!(s1, s2);

    let c1 = BehaviorEquivalenceClass::ShippedPathDrift;
    let c2 = c1;
    assert_eq!(c1, c2);

    let p1 = PublicationDisposition::NonPublicationEvidence;
    let p2 = p1;
    assert_eq!(p1, p2);

    let h1 = OwnerRouteHint::BenchmarkCorpus;
    let h2 = h1;
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_debug_format_nonempty_for_all_enum_variants() {
    let surfaces = [EvidenceSurface::ShippedPath, EvidenceSurface::LibraryOnly];
    for v in surfaces {
        assert!(!format!("{v:?}").is_empty());
    }

    let classes = [
        BehaviorEquivalenceClass::Equivalent,
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for v in classes {
        assert!(!format!("{v:?}").is_empty());
    }

    let dispositions = [
        PublicationDisposition::PublicationEligible,
        PublicationDisposition::NonPublicationEvidence,
        PublicationDisposition::Blocked,
    ];
    for v in dispositions {
        assert!(!format!("{v:?}").is_empty());
    }
}

#[test]
fn enrichment_report_clone_preserves_record_count() {
    let observations = vec![
        obs(
            "c1",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "c2",
            EvidenceSurface::LibraryOnly,
            true,
            true,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
    ];
    let report = build_report("t-clone", "d-clone", POLICY_ID, &observations);
    let cloned = report.clone();
    assert_eq!(report.records.len(), cloned.records.len());
    assert_eq!(report.owner_routes.len(), cloned.owner_routes.len());
    assert_eq!(report, cloned);
}

// =========================================================================
// V. Field invariant checks
// =========================================================================

#[test]
fn enrichment_owner_route_fields_nonempty_for_all_hints() {
    let hints = [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::TypeScriptNormalization,
        OwnerRouteHint::ShippedPathParity,
        OwnerRouteHint::BenchmarkHarness,
        OwnerRouteHint::BenchmarkCorpus,
        OwnerRouteHint::DocsContract,
    ];
    let non_equivalent_class = BehaviorEquivalenceClass::SemanticMismatch;
    for hint in hints {
        let route = route_owner(non_equivalent_class, hint).unwrap();
        assert!(
            !route.owner_bead_id.is_empty(),
            "owner_bead_id empty for {hint:?}"
        );
        assert!(!route.component.is_empty(), "component empty for {hint:?}");
        assert!(!route.rationale.is_empty(), "rationale empty for {hint:?}");
        assert!(
            route.owner_bead_id.starts_with("bd-"),
            "bead_id doesn't start with bd- for {hint:?}"
        );
    }
}

#[test]
fn enrichment_divergence_owner_route_workload_ids_sorted() {
    // Workload IDs in the aggregated route must be in sorted order (BTreeSet dedup).
    let observations = vec![
        obs(
            "zeta",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "alpha",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs(
            "mu",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
    ];
    let report = build_report("t-sort", "d-sort", POLICY_ID, &observations);
    assert_eq!(report.owner_routes.len(), 1);
    let ids = &report.owner_routes[0].workload_ids;
    assert_eq!(ids.len(), 3);
    // BTreeSet ordering means alpha < mu < zeta.
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(*ids, sorted);
}

#[test]
fn enrichment_report_schema_version_and_component_always_set() {
    let report = build_report("any-trace", "any-dec", "any-policy", &[]);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert!(!report.schema_version.is_empty());
    assert_eq!(report.component, COMPONENT);
    assert!(!report.component.is_empty());
    assert_eq!(report.policy_id, "any-policy");
    assert_eq!(report.trace_id, "any-trace");
    assert_eq!(report.decision_id, "any-dec");
}

#[test]
fn enrichment_owner_route_hint_bead_id_starts_with_bd() {
    let hints = [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::TypeScriptNormalization,
        OwnerRouteHint::ShippedPathParity,
        OwnerRouteHint::BenchmarkHarness,
        OwnerRouteHint::BenchmarkCorpus,
        OwnerRouteHint::DocsContract,
    ];
    for hint in hints {
        assert!(
            hint.owner_bead_id().starts_with("bd-"),
            "owner_bead_id for {hint:?} should start with 'bd-'"
        );
        assert!(
            !hint.component().is_empty(),
            "component for {hint:?} should be non-empty"
        );
        assert!(
            !hint.as_str().is_empty(),
            "as_str for {hint:?} should be non-empty"
        );
    }
}

#[test]
fn enrichment_evidence_surface_as_str_nonempty_and_snake_case() {
    for surface in [EvidenceSurface::ShippedPath, EvidenceSurface::LibraryOnly] {
        let s = surface.as_str();
        assert!(!s.is_empty());
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[test]
fn enrichment_equivalence_class_as_str_nonempty_and_snake_case() {
    let classes = [
        BehaviorEquivalenceClass::Equivalent,
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for class in classes {
        let s = class.as_str();
        assert!(!s.is_empty());
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
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
