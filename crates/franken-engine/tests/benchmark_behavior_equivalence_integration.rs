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

use frankenengine_engine::benchmark_behavior_equivalence::{
    BEAD_ID, BehaviorEquivalenceClass, BehaviorEquivalenceObservation, BehaviorEquivalenceReport,
    BenchmarkParityVerdictRecord, COMPONENT, DivergenceOwnerRoute, EvidenceSurface, OwnerRoute,
    OwnerRouteHint, POLICY_ID, PublicationDisposition, SCHEMA_VERSION, build_record, build_report,
    classify_observation, publication_disposition_for, route_owner,
};
use frankenengine_engine::benchmark_evidence_bundle::ParityTarget;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn shipped_obs(workload_id: &str) -> BehaviorEquivalenceObservation {
    BehaviorEquivalenceObservation::new(
        workload_id,
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
}

fn library_obs(workload_id: &str) -> BehaviorEquivalenceObservation {
    BehaviorEquivalenceObservation::new(
        workload_id,
        ParityTarget::NodeJs,
        EvidenceSurface::LibraryOnly,
        OwnerRouteHint::ModuleInterop,
    )
}

fn obs_with_baseline(
    workload_id: &str,
    baseline: ParityTarget,
    surface: EvidenceSurface,
    hint: OwnerRouteHint,
) -> BehaviorEquivalenceObservation {
    BehaviorEquivalenceObservation::new(workload_id, baseline, surface, hint)
}

// =========================================================================
// 1. Constants validation
// =========================================================================

#[test]
fn test_schema_version_value() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.benchmark-behavior-equivalence.v1"
    );
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "benchmark_behavior_equivalence");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.8.4.2");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-704B");
}

#[test]
fn test_constants_are_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
}

// =========================================================================
// 2. EvidenceSurface: as_str, Display, serde roundtrip, Ord
// =========================================================================

#[test]
fn test_evidence_surface_as_str_shipped_path() {
    assert_eq!(EvidenceSurface::ShippedPath.as_str(), "shipped_path");
}

#[test]
fn test_evidence_surface_as_str_library_only() {
    assert_eq!(EvidenceSurface::LibraryOnly.as_str(), "library_only");
}

#[test]
fn test_evidence_surface_display_matches_as_str() {
    let shipped = EvidenceSurface::ShippedPath;
    let library = EvidenceSurface::LibraryOnly;
    assert_eq!(format!("{shipped}"), shipped.as_str());
    assert_eq!(format!("{library}"), library.as_str());
}

#[test]
fn test_evidence_surface_serde_roundtrip() {
    for surface in [EvidenceSurface::ShippedPath, EvidenceSurface::LibraryOnly] {
        let json = serde_json::to_string(&surface).expect("serialize");
        let back: EvidenceSurface = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(surface, back);
    }
}

#[test]
fn test_evidence_surface_ord_shipped_before_library() {
    // Enum declaration order: ShippedPath first, LibraryOnly second
    assert!(EvidenceSurface::ShippedPath < EvidenceSurface::LibraryOnly);
}

// =========================================================================
// 3. BehaviorEquivalenceClass: as_str, blocks_publication, serde roundtrip
// =========================================================================

#[test]
fn test_equivalence_class_as_str_equivalent() {
    assert_eq!(BehaviorEquivalenceClass::Equivalent.as_str(), "equivalent");
}

#[test]
fn test_equivalence_class_as_str_semantic_mismatch() {
    assert_eq!(
        BehaviorEquivalenceClass::SemanticMismatch.as_str(),
        "semantic_mismatch"
    );
}

#[test]
fn test_equivalence_class_as_str_unsupported_feature() {
    assert_eq!(
        BehaviorEquivalenceClass::UnsupportedFeature.as_str(),
        "unsupported_feature"
    );
}

#[test]
fn test_equivalence_class_as_str_infra_failure() {
    assert_eq!(
        BehaviorEquivalenceClass::InfraFailure.as_str(),
        "infra_failure"
    );
}

#[test]
fn test_equivalence_class_as_str_benchmark_noise() {
    assert_eq!(
        BehaviorEquivalenceClass::BenchmarkNoise.as_str(),
        "benchmark_noise"
    );
}

#[test]
fn test_equivalence_class_as_str_shipped_path_drift() {
    assert_eq!(
        BehaviorEquivalenceClass::ShippedPathDrift.as_str(),
        "shipped_path_drift"
    );
}

#[test]
fn test_equivalence_class_blocks_publication_only_equivalent_is_false() {
    assert!(!BehaviorEquivalenceClass::Equivalent.blocks_publication());
    assert!(BehaviorEquivalenceClass::SemanticMismatch.blocks_publication());
    assert!(BehaviorEquivalenceClass::UnsupportedFeature.blocks_publication());
    assert!(BehaviorEquivalenceClass::InfraFailure.blocks_publication());
    assert!(BehaviorEquivalenceClass::BenchmarkNoise.blocks_publication());
    assert!(BehaviorEquivalenceClass::ShippedPathDrift.blocks_publication());
}

#[test]
fn test_equivalence_class_serde_roundtrip_all_variants() {
    let all = [
        BehaviorEquivalenceClass::Equivalent,
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for class in all {
        let json = serde_json::to_string(&class).expect("serialize");
        let back: BehaviorEquivalenceClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, back, "roundtrip failed for {class}");
    }
}

// =========================================================================
// 4. PublicationDisposition: as_str, serde
// =========================================================================

#[test]
fn test_publication_disposition_as_str_publication_eligible() {
    assert_eq!(
        PublicationDisposition::PublicationEligible.as_str(),
        "publication_eligible"
    );
}

#[test]
fn test_publication_disposition_as_str_non_publication_evidence() {
    assert_eq!(
        PublicationDisposition::NonPublicationEvidence.as_str(),
        "non_publication_evidence"
    );
}

#[test]
fn test_publication_disposition_as_str_blocked() {
    assert_eq!(PublicationDisposition::Blocked.as_str(), "blocked");
}

#[test]
fn test_publication_disposition_serde_roundtrip() {
    for disp in [
        PublicationDisposition::PublicationEligible,
        PublicationDisposition::NonPublicationEvidence,
        PublicationDisposition::Blocked,
    ] {
        let json = serde_json::to_string(&disp).expect("serialize");
        let back: PublicationDisposition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(disp, back);
    }
}

// =========================================================================
// 5. OwnerRouteHint: as_str, owner_bead_id, component for all 7
// =========================================================================

#[test]
fn test_owner_route_hint_as_str_all_variants() {
    let expected = [
        (OwnerRouteHint::RuntimeSemantics, "runtime_semantics"),
        (OwnerRouteHint::ModuleInterop, "module_interop"),
        (
            OwnerRouteHint::TypeScriptNormalization,
            "typescript_normalization",
        ),
        (OwnerRouteHint::ShippedPathParity, "shipped_path_parity"),
        (OwnerRouteHint::BenchmarkHarness, "benchmark_harness"),
        (OwnerRouteHint::BenchmarkCorpus, "benchmark_corpus"),
        (OwnerRouteHint::DocsContract, "docs_contract"),
    ];
    for (hint, name) in expected {
        assert_eq!(hint.as_str(), name, "as_str mismatch for {hint:?}");
    }
}

#[test]
fn test_owner_route_hint_owner_bead_id_all_variants() {
    let expected = [
        (OwnerRouteHint::RuntimeSemantics, "bd-1lsy.4"),
        (OwnerRouteHint::ModuleInterop, "bd-1lsy.5"),
        (OwnerRouteHint::TypeScriptNormalization, "bd-1lsy.3"),
        (OwnerRouteHint::ShippedPathParity, "bd-1lsy.9.6"),
        (OwnerRouteHint::BenchmarkHarness, BEAD_ID),
        (OwnerRouteHint::BenchmarkCorpus, "bd-1lsy.8.4.1"),
        (OwnerRouteHint::DocsContract, "bd-1lsy.10.11"),
    ];
    for (hint, bead_id) in expected {
        assert_eq!(
            hint.owner_bead_id(),
            bead_id,
            "owner_bead_id mismatch for {hint:?}"
        );
    }
}

#[test]
fn test_owner_route_hint_component_all_variants() {
    let expected = [
        (OwnerRouteHint::RuntimeSemantics, "runtime_semantics"),
        (OwnerRouteHint::ModuleInterop, "module_system_interop"),
        (OwnerRouteHint::TypeScriptNormalization, "ts_normalization"),
        (OwnerRouteHint::ShippedPathParity, "shipped_path_parity"),
        (OwnerRouteHint::BenchmarkHarness, COMPONENT),
        (OwnerRouteHint::BenchmarkCorpus, "benchmark_workload_corpus"),
        (OwnerRouteHint::DocsContract, "docs_help_surface"),
    ];
    for (hint, comp) in expected {
        assert_eq!(hint.component(), comp, "component mismatch for {hint:?}");
    }
}

#[test]
fn test_owner_route_hint_display_matches_as_str() {
    let all = [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::TypeScriptNormalization,
        OwnerRouteHint::ShippedPathParity,
        OwnerRouteHint::BenchmarkHarness,
        OwnerRouteHint::BenchmarkCorpus,
        OwnerRouteHint::DocsContract,
    ];
    for hint in all {
        assert_eq!(format!("{hint}"), hint.as_str());
    }
}

// =========================================================================
// 6. Classification priority: infra > feature > noise > output equivalence
// =========================================================================

#[test]
fn test_classify_infra_failure_overrides_all_other_flags() {
    let obs = shipped_obs("w-prio")
        .with_infra_ok(false)
        .with_feature_supported(false)
        .with_noise_only(true)
        .with_output_equivalence(false);
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::InfraFailure
    );
}

#[test]
fn test_classify_unsupported_feature_overrides_noise_and_output() {
    let obs = shipped_obs("w-prio2")
        .with_feature_supported(false)
        .with_noise_only(true)
        .with_output_equivalence(false);
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::UnsupportedFeature
    );
}

#[test]
fn test_classify_noise_overrides_output_mismatch() {
    let obs = shipped_obs("w-prio3")
        .with_noise_only(true)
        .with_output_equivalence(false);
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::BenchmarkNoise
    );
}

#[test]
fn test_classify_equivalent_when_all_flags_pass() {
    let obs = shipped_obs("w-equiv");
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::Equivalent
    );
}

// =========================================================================
// 7. Classification with shipped vs library surface
// =========================================================================

#[test]
fn test_classify_output_mismatch_shipped_yields_shipped_path_drift() {
    let obs = shipped_obs("w-ship").with_output_equivalence(false);
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::ShippedPathDrift
    );
}

#[test]
fn test_classify_output_mismatch_library_yields_semantic_mismatch() {
    let obs = library_obs("w-lib").with_output_equivalence(false);
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::SemanticMismatch
    );
}

#[test]
fn test_classify_infra_failure_same_for_both_surfaces() {
    let shipped = shipped_obs("w-s").with_infra_ok(false);
    let library = library_obs("w-l").with_infra_ok(false);
    assert_eq!(
        classify_observation(&shipped),
        BehaviorEquivalenceClass::InfraFailure
    );
    assert_eq!(
        classify_observation(&library),
        BehaviorEquivalenceClass::InfraFailure
    );
}

// =========================================================================
// 8. Publication disposition mapping for all combinations
// =========================================================================

#[test]
fn test_disposition_equivalent_shipped_is_publication_eligible() {
    assert_eq!(
        publication_disposition_for(
            BehaviorEquivalenceClass::Equivalent,
            EvidenceSurface::ShippedPath
        ),
        PublicationDisposition::PublicationEligible
    );
}

#[test]
fn test_disposition_equivalent_library_is_non_publication() {
    assert_eq!(
        publication_disposition_for(
            BehaviorEquivalenceClass::Equivalent,
            EvidenceSurface::LibraryOnly
        ),
        PublicationDisposition::NonPublicationEvidence
    );
}

#[test]
fn test_disposition_all_blocking_classes_yield_blocked_regardless_of_surface() {
    let blocking = [
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for class in blocking {
        for surface in [EvidenceSurface::ShippedPath, EvidenceSurface::LibraryOnly] {
            assert_eq!(
                publication_disposition_for(class, surface),
                PublicationDisposition::Blocked,
                "{class} + {surface} should be blocked"
            );
        }
    }
}

// =========================================================================
// 9. Owner routing
// =========================================================================

#[test]
fn test_route_owner_returns_none_for_equivalent() {
    for hint in [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::BenchmarkHarness,
    ] {
        assert!(
            route_owner(BehaviorEquivalenceClass::Equivalent, hint).is_none(),
            "Equivalent should never route for {hint:?}"
        );
    }
}

#[test]
fn test_route_owner_infra_failure_always_routes_to_harness() {
    for hint in [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::TypeScriptNormalization,
        OwnerRouteHint::DocsContract,
    ] {
        let route = route_owner(BehaviorEquivalenceClass::InfraFailure, hint)
            .expect("infra should always route");
        assert_eq!(route.owner_hint, OwnerRouteHint::BenchmarkHarness);
        assert_eq!(route.owner_bead_id, BEAD_ID);
        assert_eq!(route.component, COMPONENT);
    }
}

#[test]
fn test_route_owner_benchmark_noise_routes_to_harness() {
    let route = route_owner(
        BehaviorEquivalenceClass::BenchmarkNoise,
        OwnerRouteHint::RuntimeSemantics,
    )
    .expect("noise should route");
    assert_eq!(route.owner_hint, OwnerRouteHint::BenchmarkHarness);
    assert_eq!(route.owner_bead_id, BEAD_ID);
}

#[test]
fn test_route_owner_shipped_path_drift_routes_to_shipped_path_parity() {
    let route = route_owner(
        BehaviorEquivalenceClass::ShippedPathDrift,
        OwnerRouteHint::RuntimeSemantics,
    )
    .expect("drift should route");
    assert_eq!(route.owner_hint, OwnerRouteHint::ShippedPathParity);
    assert_eq!(route.owner_bead_id, "bd-1lsy.9.6");
    assert_eq!(route.component, "shipped_path_parity");
}

#[test]
fn test_route_owner_semantic_mismatch_preserves_hint() {
    let route = route_owner(
        BehaviorEquivalenceClass::SemanticMismatch,
        OwnerRouteHint::ModuleInterop,
    )
    .expect("mismatch should route");
    assert_eq!(route.owner_hint, OwnerRouteHint::ModuleInterop);
    assert_eq!(route.owner_bead_id, "bd-1lsy.5");
    assert_eq!(route.component, "module_system_interop");
}

#[test]
fn test_route_owner_unsupported_feature_preserves_hint() {
    let route = route_owner(
        BehaviorEquivalenceClass::UnsupportedFeature,
        OwnerRouteHint::TypeScriptNormalization,
    )
    .expect("unsupported should route");
    assert_eq!(route.owner_hint, OwnerRouteHint::TypeScriptNormalization);
    assert_eq!(route.owner_bead_id, "bd-1lsy.3");
    assert_eq!(route.component, "ts_normalization");
}

#[test]
fn test_route_owner_rationale_is_nonempty() {
    let blocking = [
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for class in blocking {
        let route =
            route_owner(class, OwnerRouteHint::RuntimeSemantics).expect("should route");
        assert!(
            !route.rationale.is_empty(),
            "rationale should be non-empty for {class}"
        );
    }
}

// =========================================================================
// 10. build_record: deterministic hash, hash sensitivity, repro command
// =========================================================================

#[test]
fn test_build_record_deterministic_hash_same_input() {
    let obs = shipped_obs("det-1").with_detail("stable");
    let r1 = build_record(&obs);
    let r2 = build_record(&obs);
    assert_eq!(r1.record_hash, r2.record_hash);
}

#[test]
fn test_build_record_hash_sensitive_to_workload_id() {
    let obs_a = shipped_obs("workload-a").with_detail("same");
    let obs_b = shipped_obs("workload-b").with_detail("same");
    assert_ne!(build_record(&obs_a).record_hash, build_record(&obs_b).record_hash);
}

#[test]
fn test_build_record_hash_sensitive_to_detail() {
    let obs_a = shipped_obs("wk").with_detail("detail-alpha");
    let obs_b = shipped_obs("wk").with_detail("detail-beta");
    assert_ne!(build_record(&obs_a).record_hash, build_record(&obs_b).record_hash);
}

#[test]
fn test_build_record_hash_sensitive_to_surface() {
    let obs_shipped = shipped_obs("wk");
    let obs_library = library_obs("wk");
    // They differ in surface (and owner_hint), so hashes differ
    assert_ne!(
        build_record(&obs_shipped).record_hash,
        build_record(&obs_library).record_hash
    );
}

#[test]
fn test_build_record_hash_sensitive_to_baseline() {
    let obs_node = obs_with_baseline(
        "wk",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );
    let obs_bun = obs_with_baseline(
        "wk",
        ParityTarget::Bun,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );
    assert_ne!(build_record(&obs_node).record_hash, build_record(&obs_bun).record_hash);
}

#[test]
fn test_build_record_repro_command_preserved() {
    let obs = shipped_obs("w-repro")
        .with_output_equivalence(false)
        .with_minimized_repro_command("frankenctl run --minimized");
    let record = build_record(&obs);
    assert_eq!(
        record.minimized_repro_command.as_deref(),
        Some("frankenctl run --minimized")
    );
}

#[test]
fn test_build_record_no_repro_command_when_not_set() {
    let obs = shipped_obs("w-no-repro");
    let record = build_record(&obs);
    assert!(record.minimized_repro_command.is_none());
}

#[test]
fn test_build_record_fields_match_observation() {
    let obs = shipped_obs("w-fields")
        .with_output_equivalence(false)
        .with_detail("my-detail");
    let record = build_record(&obs);
    assert_eq!(record.workload_id, "w-fields");
    assert_eq!(record.baseline, ParityTarget::NodeJs);
    assert_eq!(record.surface, EvidenceSurface::ShippedPath);
    assert_eq!(record.classification, BehaviorEquivalenceClass::ShippedPathDrift);
    assert_eq!(record.publication_disposition, PublicationDisposition::Blocked);
    assert_eq!(record.detail, "my-detail");
    assert!(record.owner_route.is_some());
}

// =========================================================================
// 11. build_report: empty, single, multiple observations; sorting; aggregation
// =========================================================================

#[test]
fn test_build_report_empty_observations() {
    let report = build_report("trace-empty", "dec-empty", POLICY_ID, &[]);
    assert!(report.records.is_empty());
    assert!(report.owner_routes.is_empty());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.trace_id, "trace-empty");
    assert_eq!(report.decision_id, "dec-empty");
    assert_eq!(report.policy_id, POLICY_ID);
}

#[test]
fn test_build_report_single_equivalent_observation() {
    let obs = shipped_obs("single-w");
    let report = build_report("t1", "d1", POLICY_ID, &[obs]);
    assert_eq!(report.records.len(), 1);
    assert_eq!(
        report.records[0].classification,
        BehaviorEquivalenceClass::Equivalent
    );
    assert!(report.owner_routes.is_empty());
    assert!(!report.has_publication_blockers());
}

#[test]
fn test_build_report_multiple_observations_sorted_by_workload_id() {
    let observations = vec![
        shipped_obs("zulu"),
        shipped_obs("alpha"),
        shipped_obs("mike"),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    let ids: Vec<&str> = report
        .records
        .iter()
        .map(|r| r.workload_id.as_str())
        .collect();
    assert_eq!(ids, vec!["alpha", "mike", "zulu"]);
}

#[test]
fn test_build_report_aggregates_same_owner_route() {
    // Two shipped-path drift observations from the same hint => one owner route
    let observations = vec![
        shipped_obs("w1").with_output_equivalence(false),
        shipped_obs("w2").with_output_equivalence(false),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    assert_eq!(report.owner_routes.len(), 1);
    let route = &report.owner_routes[0];
    assert_eq!(route.workload_ids.len(), 2);
    assert!(route.workload_ids.contains(&"w1".to_string()));
    assert!(route.workload_ids.contains(&"w2".to_string()));
}

#[test]
fn test_build_report_different_classifications_produce_separate_owner_routes() {
    // InfraFailure routes to harness, ShippedPathDrift routes to shipped_path_parity
    let observations = vec![
        shipped_obs("w1").with_infra_ok(false),
        shipped_obs("w2").with_output_equivalence(false),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    // InfraFailure -> BenchmarkHarness, ShippedPathDrift -> ShippedPathParity
    // These have different owner_bead_ids, so 2 routes
    assert_eq!(report.owner_routes.len(), 2);
}

#[test]
fn test_build_report_has_publication_blockers_false_when_all_equivalent() {
    let observations = vec![shipped_obs("w1"), shipped_obs("w2"), shipped_obs("w3")];
    let report = build_report("t", "d", POLICY_ID, &observations);
    assert!(!report.has_publication_blockers());
}

#[test]
fn test_build_report_has_publication_blockers_true_when_any_blocked() {
    let observations = vec![
        shipped_obs("w1"),
        shipped_obs("w2").with_output_equivalence(false),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    assert!(report.has_publication_blockers());
}

// =========================================================================
// 12. JSONL and JSON serialization of reports
// =========================================================================

#[test]
fn test_benchmark_parity_verdict_jsonl_two_records() {
    let report = build_report(
        "t-jsonl",
        "d-jsonl",
        POLICY_ID,
        &[shipped_obs("w1"), shipped_obs("w2")],
    );
    let jsonl = report
        .benchmark_parity_verdict_jsonl()
        .expect("should render jsonl");
    let lines: Vec<&str> = jsonl.split('\n').collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let parsed: BenchmarkParityVerdictRecord =
            serde_json::from_str(line).expect("each line should parse");
        assert_eq!(parsed.classification, BehaviorEquivalenceClass::Equivalent);
    }
}

#[test]
fn test_benchmark_parity_verdict_jsonl_empty_report() {
    let report = build_report("t", "d", POLICY_ID, &[]);
    let jsonl = report
        .benchmark_parity_verdict_jsonl()
        .expect("should render");
    assert!(jsonl.is_empty());
}

#[test]
fn test_divergence_owner_route_json_renders_valid_json() {
    let obs = shipped_obs("w-json").with_output_equivalence(false);
    let report = build_report("t", "d", POLICY_ID, &[obs]);
    let json_str = report
        .divergence_owner_route_json()
        .expect("should render");
    let routes: Vec<DivergenceOwnerRoute> =
        serde_json::from_str(&json_str).expect("should parse back");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].owner_hint, OwnerRouteHint::ShippedPathParity);
}

#[test]
fn test_divergence_owner_route_json_empty_when_all_equivalent() {
    let report = build_report("t", "d", POLICY_ID, &[shipped_obs("w1")]);
    let json_str = report
        .divergence_owner_route_json()
        .expect("should render");
    let routes: Vec<DivergenceOwnerRoute> =
        serde_json::from_str(&json_str).expect("should parse back");
    assert!(routes.is_empty());
}

// =========================================================================
// 13. Serde roundtrips for observations and reports
// =========================================================================

#[test]
fn test_observation_serde_roundtrip_with_all_fields() {
    let obs = shipped_obs("serde-obs")
        .with_output_equivalence(false)
        .with_feature_supported(false)
        .with_infra_ok(false)
        .with_noise_only(true)
        .with_detail("serde-detail")
        .with_minimized_repro_command("cmd --flag");
    let json = serde_json::to_string(&obs).expect("serialize");
    let back: BehaviorEquivalenceObservation =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, back);
}

#[test]
fn test_observation_serde_roundtrip_minimal() {
    let obs = shipped_obs("minimal");
    let json = serde_json::to_string(&obs).expect("serialize");
    let back: BehaviorEquivalenceObservation =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, back);
}

#[test]
fn test_record_serde_roundtrip() {
    let obs = shipped_obs("rec-serde").with_output_equivalence(false);
    let record = build_record(&obs);
    let json = serde_json::to_string(&record).expect("serialize");
    let back: BenchmarkParityVerdictRecord =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, back);
}

#[test]
fn test_report_serde_roundtrip() {
    let observations = vec![
        shipped_obs("w1"),
        shipped_obs("w2").with_output_equivalence(false),
    ];
    let report = build_report("trace-rt", "dec-rt", POLICY_ID, &observations);
    let json = serde_json::to_string(&report).expect("serialize");
    let back: BehaviorEquivalenceReport =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, back);
}

#[test]
fn test_owner_route_serde_roundtrip() {
    let route = route_owner(
        BehaviorEquivalenceClass::SemanticMismatch,
        OwnerRouteHint::DocsContract,
    )
    .expect("should route");
    let json = serde_json::to_string(&route).expect("serialize");
    let back: OwnerRoute = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(route, back);
}

#[test]
fn test_divergence_owner_route_serde_roundtrip() {
    let obs = shipped_obs("div-serde").with_output_equivalence(false);
    let report = build_report("t", "d", POLICY_ID, &[obs]);
    assert!(!report.owner_routes.is_empty());
    let json = serde_json::to_string(&report.owner_routes[0]).expect("serialize");
    let back: DivergenceOwnerRoute = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report.owner_routes[0], back);
}

// =========================================================================
// 14. Batch scenarios: mixed, all-equivalent, all-blocked
// =========================================================================

#[test]
fn test_batch_mixed_classifications() {
    let observations = vec![
        shipped_obs("equiv").with_detail("clean"),
        shipped_obs("infra").with_infra_ok(false).with_detail("timeout"),
        shipped_obs("drift")
            .with_output_equivalence(false)
            .with_detail("output diff"),
        library_obs("lib-mismatch")
            .with_output_equivalence(false)
            .with_detail("semantic diff"),
        shipped_obs("noise")
            .with_noise_only(true)
            .with_detail("variance"),
        shipped_obs("unsup")
            .with_feature_supported(false)
            .with_detail("no ESM"),
    ];
    let report = build_report("trace-mix", "dec-mix", POLICY_ID, &observations);

    assert_eq!(report.records.len(), 6);
    assert!(report.has_publication_blockers());

    // Count classifications
    let equiv_count = report
        .records
        .iter()
        .filter(|r| r.classification == BehaviorEquivalenceClass::Equivalent)
        .count();
    assert_eq!(equiv_count, 1);

    let blocked_count = report
        .records
        .iter()
        .filter(|r| r.publication_disposition == PublicationDisposition::Blocked)
        .count();
    assert_eq!(blocked_count, 5);
}

#[test]
fn test_batch_all_equivalent() {
    let observations: Vec<_> = (0..10)
        .map(|i| shipped_obs(&format!("w-{i}")))
        .collect();
    let report = build_report("t-all-eq", "d-all-eq", POLICY_ID, &observations);
    assert_eq!(report.records.len(), 10);
    assert!(!report.has_publication_blockers());
    assert!(report.owner_routes.is_empty());
    for record in &report.records {
        assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
        assert_eq!(
            record.publication_disposition,
            PublicationDisposition::PublicationEligible
        );
        assert!(record.owner_route.is_none());
    }
}

#[test]
fn test_batch_all_blocked() {
    let observations: Vec<_> = (0..5)
        .map(|i| shipped_obs(&format!("blocked-{i}")).with_infra_ok(false))
        .collect();
    let report = build_report("t-block", "d-block", POLICY_ID, &observations);
    assert!(report.has_publication_blockers());
    for record in &report.records {
        assert_eq!(record.publication_disposition, PublicationDisposition::Blocked);
        assert!(record.owner_route.is_some());
    }
    // All infra failures route to same owner (BenchmarkHarness), so 1 aggregated route
    assert_eq!(report.owner_routes.len(), 1);
    assert_eq!(report.owner_routes[0].workload_ids.len(), 5);
}

// =========================================================================
// 15. Edge cases
// =========================================================================

#[test]
fn test_empty_detail_string() {
    let obs = shipped_obs("empty-detail");
    assert!(obs.detail.is_empty());
    let record = build_record(&obs);
    assert!(record.detail.is_empty());
}

#[test]
fn test_multiple_workloads_same_owner_route_aggregated() {
    // 3 infra failures with different workload IDs all route to harness
    let observations: Vec<_> = ["alpha", "beta", "gamma"]
        .iter()
        .map(|id| shipped_obs(id).with_infra_ok(false))
        .collect();
    let report = build_report("t", "d", POLICY_ID, &observations);
    assert_eq!(report.owner_routes.len(), 1);
    let route = &report.owner_routes[0];
    assert_eq!(route.workload_ids, vec!["alpha", "beta", "gamma"]);
    assert_eq!(
        route.classifications,
        vec![BehaviorEquivalenceClass::InfraFailure]
    );
}

#[test]
fn test_all_parity_targets_as_baseline() {
    for target in ParityTarget::ALL {
        let obs = obs_with_baseline(
            "parity-test",
            *target,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        );
        let record = build_record(&obs);
        assert_eq!(record.baseline, *target);
        assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
    }
}

#[test]
fn test_all_parity_targets_produce_distinct_hashes() {
    let hashes: Vec<_> = ParityTarget::ALL
        .iter()
        .map(|target| {
            let obs = obs_with_baseline(
                "same-wk",
                *target,
                EvidenceSurface::ShippedPath,
                OwnerRouteHint::RuntimeSemantics,
            );
            build_record(&obs).record_hash
        })
        .collect();
    // All 4 hashes should be unique
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j], "hash collision between target {i} and {j}");
        }
    }
}

#[test]
fn test_report_records_sorted_by_baseline_within_same_workload() {
    let observations = vec![
        obs_with_baseline(
            "same-wk",
            ParityTarget::V8Isolate,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs_with_baseline(
            "same-wk",
            ParityTarget::Bun,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs_with_baseline(
            "same-wk",
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        ),
        obs_with_baseline(
            "same-wk",
            ParityTarget::Deno,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        ),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    // Sorted by baseline.as_str() since workload_id is the same
    let baselines: Vec<&str> = report
        .records
        .iter()
        .map(|r| r.baseline.as_str())
        .collect();
    let mut sorted = baselines.clone();
    sorted.sort();
    assert_eq!(baselines, sorted);
}

#[test]
fn test_hash_sensitive_to_minimized_repro_command() {
    let obs_with = shipped_obs("wk").with_minimized_repro_command("repro --test");
    let obs_without = shipped_obs("wk");
    assert_ne!(
        build_record(&obs_with).record_hash,
        build_record(&obs_without).record_hash
    );
}

#[test]
fn test_hash_sensitive_to_classification_via_flags() {
    let obs_ok = shipped_obs("wk");
    let obs_infra = shipped_obs("wk").with_infra_ok(false);
    assert_ne!(
        build_record(&obs_ok).record_hash,
        build_record(&obs_infra).record_hash
    );
}

#[test]
fn test_observation_builder_chaining_order_independent() {
    let obs_a = shipped_obs("wk")
        .with_output_equivalence(false)
        .with_detail("d")
        .with_noise_only(true);
    let obs_b = shipped_obs("wk")
        .with_noise_only(true)
        .with_detail("d")
        .with_output_equivalence(false);
    assert_eq!(obs_a, obs_b);
}

#[test]
fn test_observation_builder_defaults() {
    let obs = shipped_obs("defaults");
    assert!(obs.output_equivalent);
    assert!(obs.feature_supported);
    assert!(obs.infra_ok);
    assert!(!obs.noise_only);
    assert!(obs.detail.is_empty());
    assert!(obs.minimized_repro_command.is_none());
}

#[test]
fn test_divergence_owner_route_classifications_deduped() {
    // Three records with same classification and owner route
    let observations = vec![
        shipped_obs("w1").with_infra_ok(false),
        shipped_obs("w2").with_infra_ok(false),
        shipped_obs("w3").with_infra_ok(false),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    assert_eq!(report.owner_routes.len(), 1);
    // Classifications should be de-duped via BTreeSet
    assert_eq!(report.owner_routes[0].classifications.len(), 1);
    assert_eq!(
        report.owner_routes[0].classifications[0],
        BehaviorEquivalenceClass::InfraFailure
    );
}

#[test]
fn test_divergence_owner_route_workload_ids_sorted() {
    let observations = vec![
        shipped_obs("zeta").with_infra_ok(false),
        shipped_obs("alpha").with_infra_ok(false),
        shipped_obs("mu").with_infra_ok(false),
    ];
    let report = build_report("t", "d", POLICY_ID, &observations);
    assert_eq!(report.owner_routes.len(), 1);
    // workload_ids collected via BTreeSet, so sorted
    assert_eq!(
        report.owner_routes[0].workload_ids,
        vec!["alpha", "mu", "zeta"]
    );
}

#[test]
fn test_report_schema_version_and_component_always_set() {
    let report = build_report("t", "d", "custom-policy", &[]);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.policy_id, "custom-policy");
}

#[test]
fn test_record_equivalent_shipped_has_no_owner_route() {
    let record = build_record(&shipped_obs("clean-w"));
    assert!(record.owner_route.is_none());
    assert_eq!(
        record.publication_disposition,
        PublicationDisposition::PublicationEligible
    );
}

#[test]
fn test_record_equivalent_library_has_no_owner_route() {
    let record = build_record(&library_obs("clean-lib"));
    assert!(record.owner_route.is_none());
    assert_eq!(
        record.publication_disposition,
        PublicationDisposition::NonPublicationEvidence
    );
}
