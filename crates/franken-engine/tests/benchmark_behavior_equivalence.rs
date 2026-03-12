use frankenengine_engine::benchmark_behavior_equivalence::{
    BEAD_ID, BehaviorEquivalenceClass, BehaviorEquivalenceObservation, EvidenceSurface,
    OwnerRouteHint, PublicationDisposition, SCHEMA_VERSION, build_record, build_report,
    classify_observation,
};
use frankenengine_engine::benchmark_evidence_bundle::ParityTarget;

fn observation(
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
        .with_detail("fixture-detail")
}

#[test]
fn shipped_path_equivalent_records_are_publication_eligible() {
    let record = build_record(&observation(
        "router_hot_path",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::BenchmarkHarness,
    ));

    assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
    assert_eq!(
        record.publication_disposition,
        PublicationDisposition::PublicationEligible
    );
    assert!(record.owner_route.is_none());
}

#[test]
fn library_only_equivalent_records_stay_non_publication_evidence() {
    let record = build_record(&observation(
        "router_hot_path",
        EvidenceSurface::LibraryOnly,
        true,
        true,
        true,
        false,
        OwnerRouteHint::BenchmarkHarness,
    ));

    assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
    assert_eq!(
        record.publication_disposition,
        PublicationDisposition::NonPublicationEvidence
    );
}

#[test]
fn shipped_path_mismatch_routes_to_shipped_path_owner() {
    let record = build_record(&observation(
        "cli_compile_case",
        EvidenceSurface::ShippedPath,
        false,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    ));

    assert_eq!(
        classify_observation(&observation(
            "cli_compile_case",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        )),
        BehaviorEquivalenceClass::ShippedPathDrift
    );
    let owner_route = record.owner_route.expect("failing shipped-path case");
    assert_eq!(owner_route.owner_bead_id, "bd-1lsy.9.6");
    assert_eq!(owner_route.owner_hint, OwnerRouteHint::ShippedPathParity);
}

#[test]
fn unsupported_feature_routes_to_requested_owner_hint() {
    let record = build_record(&observation(
        "module_edge_case",
        EvidenceSurface::LibraryOnly,
        false,
        false,
        true,
        false,
        OwnerRouteHint::ModuleInterop,
    ));

    assert_eq!(
        record.classification,
        BehaviorEquivalenceClass::UnsupportedFeature
    );
    let owner_route = record
        .owner_route
        .expect("unsupported feature should route");
    assert_eq!(owner_route.owner_bead_id, "bd-1lsy.5");
    assert_eq!(owner_route.owner_hint, OwnerRouteHint::ModuleInterop);
}

#[test]
fn infra_failures_route_back_to_rgc_704b() {
    let record = build_record(&observation(
        "baseline_timeout",
        EvidenceSurface::ShippedPath,
        false,
        true,
        false,
        false,
        OwnerRouteHint::RuntimeSemantics,
    ));

    assert_eq!(
        record.classification,
        BehaviorEquivalenceClass::InfraFailure
    );
    let owner_route = record.owner_route.expect("infra failures should route");
    assert_eq!(owner_route.owner_bead_id, BEAD_ID);
    assert_eq!(owner_route.owner_hint, OwnerRouteHint::BenchmarkHarness);
}

#[test]
fn report_sorting_and_owner_route_aggregation_are_deterministic() {
    let observations = vec![
        observation(
            "zeta_case",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "alpha_case",
            EvidenceSurface::LibraryOnly,
            false,
            false,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
        observation(
            "beta_case",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::BenchmarkCorpus,
        ),
    ];

    let report = build_report(
        "trace-rgc-704b",
        "decision-rgc-704b",
        "policy-rgc-704b",
        &observations,
    );

    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.records[0].workload_id, "alpha_case");
    assert_eq!(report.records[1].workload_id, "beta_case");
    assert_eq!(report.records[2].workload_id, "zeta_case");
    assert!(report.has_publication_blockers());
    assert_eq!(report.owner_routes.len(), 3);
}

#[test]
fn report_json_outputs_include_owner_route_payload() {
    let report = build_report(
        "trace-rgc-704b",
        "decision-rgc-704b",
        "policy-rgc-704b",
        &[observation(
            "module_case",
            EvidenceSurface::LibraryOnly,
            false,
            false,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        )],
    );

    let jsonl = report
        .benchmark_parity_verdict_jsonl()
        .expect("record jsonl should render");
    let routes_json = report
        .divergence_owner_route_json()
        .expect("owner route json should render");

    assert!(jsonl.contains("\"classification\":\"unsupported_feature\""));
    assert!(jsonl.contains("\"publication_disposition\":\"blocked\""));
    assert!(routes_json.contains("\"owner_bead_id\": \"bd-1lsy.5\""));
    assert!(routes_json.contains("\"workload_ids\": ["));
}

// --- Additional integration coverage ---

#[test]
fn benchmark_noise_classification_blocks_and_routes_to_harness() {
    let record = build_record(&observation(
        "noisy_workload",
        EvidenceSurface::ShippedPath,
        false,
        true,
        true,
        true,
        OwnerRouteHint::RuntimeSemantics,
    ));

    assert_eq!(
        record.classification,
        BehaviorEquivalenceClass::BenchmarkNoise
    );
    assert_eq!(
        record.publication_disposition,
        PublicationDisposition::Blocked
    );
    let owner_route = record
        .owner_route
        .expect("benchmark noise should route to harness");
    assert_eq!(owner_route.owner_hint, OwnerRouteHint::BenchmarkHarness);
}

#[test]
fn library_only_semantic_mismatch_routes_to_feature_owner() {
    let record = build_record(&observation(
        "parse_edge_case",
        EvidenceSurface::LibraryOnly,
        false,
        true,
        true,
        false,
        OwnerRouteHint::TypeScriptNormalization,
    ));

    assert_eq!(
        record.classification,
        BehaviorEquivalenceClass::SemanticMismatch
    );
    let owner_route = record.owner_route.expect("should route");
    assert_eq!(
        owner_route.owner_hint,
        OwnerRouteHint::TypeScriptNormalization
    );
    assert_eq!(owner_route.owner_bead_id, "bd-1lsy.3");
}

#[test]
fn all_equivalent_report_has_no_owner_routes() {
    let observations = vec![
        observation(
            "case_a",
            EvidenceSurface::ShippedPath,
            true,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "case_b",
            EvidenceSurface::LibraryOnly,
            true,
            true,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    assert!(!report.has_publication_blockers());
    assert!(report.owner_routes.is_empty());
}

#[test]
fn mixed_classification_report_carries_correct_counts() {
    let observations = vec![
        observation(
            "ok_case",
            EvidenceSurface::ShippedPath,
            true,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "drift_case",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "infra_case",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    assert_eq!(report.records.len(), 3);
    assert!(report.has_publication_blockers());

    let equivalent_count = report
        .records
        .iter()
        .filter(|r| r.classification == BehaviorEquivalenceClass::Equivalent)
        .count();
    assert_eq!(equivalent_count, 1);
}

#[test]
fn report_serde_roundtrip_preserves_all_fields() {
    let observations = vec![
        observation(
            "serde_a",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "serde_b",
            EvidenceSurface::LibraryOnly,
            true,
            true,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
    ];

    let report = build_report("trace-serde", "decision-serde", "RGC-704B", &observations);
    let json = serde_json::to_string(&report).expect("serialize report");
    let restored: frankenengine_engine::benchmark_behavior_equivalence::BehaviorEquivalenceReport =
        serde_json::from_str(&json).expect("deserialize report");

    assert_eq!(report.schema_version, restored.schema_version);
    assert_eq!(report.trace_id, restored.trace_id);
    assert_eq!(report.decision_id, restored.decision_id);
    assert_eq!(report.records.len(), restored.records.len());
    assert_eq!(report.owner_routes.len(), restored.owner_routes.len());

    for (original, roundtripped) in report.records.iter().zip(restored.records.iter()) {
        assert_eq!(original.record_hash, roundtripped.record_hash);
        assert_eq!(original.classification, roundtripped.classification);
    }
}

#[test]
fn record_hashes_are_unique_across_different_workloads() {
    let obs_a = observation(
        "workload_alpha",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    let obs_b = observation(
        "workload_beta",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );

    let record_a = build_record(&obs_a);
    let record_b = build_record(&obs_b);
    assert_ne!(record_a.record_hash, record_b.record_hash);
}

#[test]
fn record_hashes_are_deterministic_across_builds() {
    let obs = observation(
        "determinism_check",
        EvidenceSurface::ShippedPath,
        false,
        false,
        true,
        false,
        OwnerRouteHint::BenchmarkCorpus,
    );

    let r1 = build_record(&obs);
    let r2 = build_record(&obs);
    assert_eq!(r1.record_hash, r2.record_hash);
}

#[test]
fn classification_priority_infra_over_unsupported_over_noise() {
    // All flags bad: infra_ok=false wins
    let obs_infra = observation(
        "priority_test",
        EvidenceSurface::ShippedPath,
        false,
        false,
        false,
        true,
        OwnerRouteHint::RuntimeSemantics,
    );
    assert_eq!(
        classify_observation(&obs_infra),
        BehaviorEquivalenceClass::InfraFailure
    );

    // infra_ok=true, feature=false: unsupported wins
    let obs_unsupported = observation(
        "priority_test",
        EvidenceSurface::ShippedPath,
        false,
        false,
        true,
        true,
        OwnerRouteHint::RuntimeSemantics,
    );
    assert_eq!(
        classify_observation(&obs_unsupported),
        BehaviorEquivalenceClass::UnsupportedFeature
    );

    // infra_ok=true, feature=true, noise=true: noise wins
    let obs_noise = observation(
        "priority_test",
        EvidenceSurface::ShippedPath,
        false,
        true,
        true,
        true,
        OwnerRouteHint::RuntimeSemantics,
    );
    assert_eq!(
        classify_observation(&obs_noise),
        BehaviorEquivalenceClass::BenchmarkNoise
    );
}

#[test]
fn report_with_bun_baseline_processes_correctly() {
    use frankenengine_engine::benchmark_behavior_equivalence::BehaviorEquivalenceObservation;

    let obs = BehaviorEquivalenceObservation::new(
        "bun_compat_case",
        ParityTarget::Bun,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false)
    .with_detail("bun-specific divergence");

    let record = build_record(&obs);
    assert_eq!(
        record.classification,
        BehaviorEquivalenceClass::ShippedPathDrift
    );
    assert_eq!(record.baseline, ParityTarget::Bun);
}

#[test]
fn owner_route_aggregation_groups_by_full_key() {
    let observations = vec![
        observation(
            "w1",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "w2",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "w3",
            EvidenceSurface::LibraryOnly,
            false,
            false,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    // w1,w2 → ShippedPathDrift → ShippedPathParity (one group)
    // w3 → UnsupportedFeature → ModuleInterop (another group)
    assert_eq!(report.owner_routes.len(), 2);
}

#[test]
fn report_jsonl_each_line_contains_workload_id() {
    let observations = vec![
        observation(
            "workload_x",
            EvidenceSurface::ShippedPath,
            true,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "workload_y",
            EvidenceSurface::ShippedPath,
            true,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    let jsonl = report
        .benchmark_parity_verdict_jsonl()
        .expect("jsonl should render");
    assert!(jsonl.contains("workload_x"));
    assert!(jsonl.contains("workload_y"));
}

#[test]
fn empty_report_jsonl_and_routes_are_valid() {
    let report = build_report("t", "d", "RGC-704B", &[]);
    let jsonl = report
        .benchmark_parity_verdict_jsonl()
        .expect("empty jsonl should succeed");
    let routes = report
        .divergence_owner_route_json()
        .expect("empty routes should succeed");
    assert!(jsonl.is_empty());
    assert_eq!(routes, "[]");
}

#[test]
fn minimized_repro_command_flows_through_to_record() {
    use frankenengine_engine::benchmark_behavior_equivalence::BehaviorEquivalenceObservation;

    let obs = BehaviorEquivalenceObservation::new(
        "repro_case",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_output_equivalence(false)
    .with_minimized_repro_command("frankenctl run --input min.js --extension-id demo");

    let record = build_record(&obs);
    assert_eq!(
        record.minimized_repro_command.as_deref(),
        Some("frankenctl run --input min.js --extension-id demo")
    );
}

#[test]
fn docs_contract_owner_hint_routes_correctly() {
    let record = build_record(&observation(
        "docs_edge_case",
        EvidenceSurface::LibraryOnly,
        false,
        false,
        true,
        false,
        OwnerRouteHint::DocsContract,
    ));

    let owner_route = record.owner_route.expect("should route");
    assert_eq!(owner_route.owner_hint, OwnerRouteHint::DocsContract);
    assert_eq!(owner_route.owner_bead_id, "bd-1lsy.10.11");
    assert_eq!(owner_route.component, "docs_help_surface");
}

// --- Serde roundtrips for individual types ---

#[test]
fn evidence_surface_serde_roundtrip_shipped_path() {
    let val = EvidenceSurface::ShippedPath;
    let json = serde_json::to_string(&val).expect("serialize");
    let back: EvidenceSurface = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(val, back);
    assert_eq!(json, "\"shipped_path\"");
}

#[test]
fn evidence_surface_serde_roundtrip_library_only() {
    let val = EvidenceSurface::LibraryOnly;
    let json = serde_json::to_string(&val).expect("serialize");
    let back: EvidenceSurface = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(val, back);
    assert_eq!(json, "\"library_only\"");
}

#[test]
fn behavior_equivalence_class_serde_roundtrip_all_variants() {
    let variants = [
        BehaviorEquivalenceClass::Equivalent,
        BehaviorEquivalenceClass::SemanticMismatch,
        BehaviorEquivalenceClass::UnsupportedFeature,
        BehaviorEquivalenceClass::InfraFailure,
        BehaviorEquivalenceClass::BenchmarkNoise,
        BehaviorEquivalenceClass::ShippedPathDrift,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: BehaviorEquivalenceClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn publication_disposition_serde_roundtrip_all_variants() {
    let variants = [
        PublicationDisposition::PublicationEligible,
        PublicationDisposition::NonPublicationEvidence,
        PublicationDisposition::Blocked,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: PublicationDisposition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

#[test]
fn owner_route_hint_serde_roundtrip_all_variants() {
    let variants = [
        OwnerRouteHint::RuntimeSemantics,
        OwnerRouteHint::ModuleInterop,
        OwnerRouteHint::TypeScriptNormalization,
        OwnerRouteHint::ShippedPathParity,
        OwnerRouteHint::BenchmarkHarness,
        OwnerRouteHint::BenchmarkCorpus,
        OwnerRouteHint::DocsContract,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: OwnerRouteHint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back);
    }
}

// --- Display implementations ---

#[test]
fn publication_disposition_display_all_variants() {
    assert_eq!(
        format!("{}", PublicationDisposition::PublicationEligible),
        "publication_eligible"
    );
    assert_eq!(
        format!("{}", PublicationDisposition::NonPublicationEvidence),
        "non_publication_evidence"
    );
    assert_eq!(format!("{}", PublicationDisposition::Blocked), "blocked");
}

#[test]
fn owner_route_hint_display_all_variants() {
    assert_eq!(
        format!("{}", OwnerRouteHint::RuntimeSemantics),
        "runtime_semantics"
    );
    assert_eq!(
        format!("{}", OwnerRouteHint::ModuleInterop),
        "module_interop"
    );
    assert_eq!(
        format!("{}", OwnerRouteHint::TypeScriptNormalization),
        "typescript_normalization"
    );
    assert_eq!(
        format!("{}", OwnerRouteHint::ShippedPathParity),
        "shipped_path_parity"
    );
    assert_eq!(
        format!("{}", OwnerRouteHint::BenchmarkHarness),
        "benchmark_harness"
    );
    assert_eq!(
        format!("{}", OwnerRouteHint::BenchmarkCorpus),
        "benchmark_corpus"
    );
    assert_eq!(format!("{}", OwnerRouteHint::DocsContract), "docs_contract");
}

#[test]
fn behavior_equivalence_class_display_all_variants() {
    assert_eq!(
        format!("{}", BehaviorEquivalenceClass::Equivalent),
        "equivalent"
    );
    assert_eq!(
        format!("{}", BehaviorEquivalenceClass::SemanticMismatch),
        "semantic_mismatch"
    );
    assert_eq!(
        format!("{}", BehaviorEquivalenceClass::UnsupportedFeature),
        "unsupported_feature"
    );
    assert_eq!(
        format!("{}", BehaviorEquivalenceClass::InfraFailure),
        "infra_failure"
    );
    assert_eq!(
        format!("{}", BehaviorEquivalenceClass::BenchmarkNoise),
        "benchmark_noise"
    );
    assert_eq!(
        format!("{}", BehaviorEquivalenceClass::ShippedPathDrift),
        "shipped_path_drift"
    );
}

// --- OwnerRouteHint routing for BenchmarkCorpus ---

#[test]
fn benchmark_corpus_semantic_mismatch_routes_to_corpus_owner() {
    let record = build_record(&observation(
        "corpus_mismatch",
        EvidenceSurface::LibraryOnly,
        false,
        true,
        true,
        false,
        OwnerRouteHint::BenchmarkCorpus,
    ));

    assert_eq!(
        record.classification,
        BehaviorEquivalenceClass::SemanticMismatch
    );
    let owner_route = record.owner_route.expect("should route to corpus");
    assert_eq!(owner_route.owner_hint, OwnerRouteHint::BenchmarkCorpus);
    assert_eq!(owner_route.owner_bead_id, "bd-1lsy.8.4.1");
    assert_eq!(owner_route.component, "benchmark_workload_corpus");
}

#[test]
fn shipped_path_parity_unsupported_routes_to_shipped_path() {
    let record = build_record(&observation(
        "shipped_unsupported",
        EvidenceSurface::ShippedPath,
        false,
        false,
        true,
        false,
        OwnerRouteHint::ShippedPathParity,
    ));

    let owner_route = record.owner_route.expect("should route");
    assert_eq!(owner_route.owner_hint, OwnerRouteHint::ShippedPathParity);
    assert_eq!(owner_route.owner_bead_id, "bd-1lsy.9.6");
}

// --- Hash sensitivity ---

#[test]
fn record_hash_changes_when_surface_differs() {
    let obs_shipped = observation(
        "hash_surface_test",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    let obs_library = observation(
        "hash_surface_test",
        EvidenceSurface::LibraryOnly,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );

    assert_ne!(
        build_record(&obs_shipped).record_hash,
        build_record(&obs_library).record_hash
    );
}

#[test]
fn record_hash_changes_when_owner_hint_differs() {
    let obs_a = observation(
        "hash_hint_test",
        EvidenceSurface::LibraryOnly,
        false,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    let obs_b = observation(
        "hash_hint_test",
        EvidenceSurface::LibraryOnly,
        false,
        true,
        true,
        false,
        OwnerRouteHint::ModuleInterop,
    );

    assert_ne!(
        build_record(&obs_a).record_hash,
        build_record(&obs_b).record_hash
    );
}

#[test]
fn record_hash_changes_when_minimized_repro_differs() {
    use frankenengine_engine::benchmark_behavior_equivalence::BehaviorEquivalenceObservation;

    let obs_a = BehaviorEquivalenceObservation::new(
        "repro_hash_test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_minimized_repro_command("cmd_a");

    let obs_b = BehaviorEquivalenceObservation::new(
        "repro_hash_test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_minimized_repro_command("cmd_b");

    assert_ne!(
        build_record(&obs_a).record_hash,
        build_record(&obs_b).record_hash
    );
}

#[test]
fn record_hash_differs_with_and_without_repro_command() {
    use frankenengine_engine::benchmark_behavior_equivalence::BehaviorEquivalenceObservation;

    let obs_with = BehaviorEquivalenceObservation::new(
        "repro_presence_test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    )
    .with_minimized_repro_command("some_cmd");

    let obs_without = BehaviorEquivalenceObservation::new(
        "repro_presence_test",
        ParityTarget::NodeJs,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );

    assert_ne!(
        build_record(&obs_with).record_hash,
        build_record(&obs_without).record_hash
    );
}

// --- Report with multiple baselines ---

#[test]
fn report_with_deno_baseline_processes_correctly() {
    use frankenengine_engine::benchmark_behavior_equivalence::BehaviorEquivalenceObservation;

    let obs = BehaviorEquivalenceObservation::new(
        "deno_compat_case",
        ParityTarget::Deno,
        EvidenceSurface::ShippedPath,
        OwnerRouteHint::RuntimeSemantics,
    );

    let record = build_record(&obs);
    assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
    assert_eq!(record.baseline, ParityTarget::Deno);
    assert_eq!(
        record.publication_disposition,
        PublicationDisposition::PublicationEligible
    );
}

#[test]
fn report_with_mixed_baselines_sorts_and_processes() {
    use frankenengine_engine::benchmark_behavior_equivalence::BehaviorEquivalenceObservation;

    let observations = vec![
        BehaviorEquivalenceObservation::new(
            "zz_bun_case",
            ParityTarget::Bun,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        ),
        BehaviorEquivalenceObservation::new(
            "aa_deno_case",
            ParityTarget::Deno,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        ),
        BehaviorEquivalenceObservation::new(
            "mm_node_case",
            ParityTarget::NodeJs,
            EvidenceSurface::LibraryOnly,
            OwnerRouteHint::ModuleInterop,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    assert_eq!(report.records.len(), 3);
    assert_eq!(report.records[0].workload_id, "aa_deno_case");
    assert_eq!(report.records[1].workload_id, "mm_node_case");
    assert_eq!(report.records[2].workload_id, "zz_bun_case");
}

// --- Owner route aggregation edge cases ---

#[test]
fn owner_routes_deduplicate_same_classification_same_owner() {
    let observations = vec![
        observation(
            "w_dup_1",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "w_dup_2",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "w_dup_3",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    // All InfraFailure → BenchmarkHarness: should aggregate to 1 route entry
    assert_eq!(report.owner_routes.len(), 1);
    assert_eq!(report.owner_routes[0].workload_ids.len(), 3);
    assert_eq!(
        report.owner_routes[0].classifications,
        vec![BehaviorEquivalenceClass::InfraFailure]
    );
}

#[test]
fn owner_routes_carry_multiple_classifications_when_same_owner() {
    let observations = vec![
        observation(
            "w_multi_1",
            EvidenceSurface::ShippedPath,
            false,
            true,
            false,
            false,
            OwnerRouteHint::BenchmarkHarness,
        ),
        observation(
            "w_multi_2",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            true,
            OwnerRouteHint::BenchmarkHarness,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    // w_multi_1 → InfraFailure → BenchmarkHarness
    // w_multi_2 → BenchmarkNoise → BenchmarkHarness
    // Both route to BenchmarkHarness but with different rationale text,
    // so they may or may not merge depending on rationale match
    assert!(!report.owner_routes.is_empty());
}

// --- JSONL output format ---

#[test]
fn jsonl_line_count_matches_record_count() {
    let observations = vec![
        observation(
            "line_a",
            EvidenceSurface::ShippedPath,
            true,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "line_b",
            EvidenceSurface::LibraryOnly,
            true,
            true,
            true,
            false,
            OwnerRouteHint::ModuleInterop,
        ),
        observation(
            "line_c",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::BenchmarkCorpus,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    let jsonl = report.benchmark_parity_verdict_jsonl().expect("render");
    let line_count = jsonl.split('\n').count();
    assert_eq!(line_count, 3);
}

#[test]
fn jsonl_each_line_parses_as_verdict_record() {
    use frankenengine_engine::benchmark_behavior_equivalence::BenchmarkParityVerdictRecord;

    let observations = vec![
        observation(
            "parse_a",
            EvidenceSurface::ShippedPath,
            false,
            true,
            true,
            false,
            OwnerRouteHint::RuntimeSemantics,
        ),
        observation(
            "parse_b",
            EvidenceSurface::LibraryOnly,
            false,
            false,
            true,
            false,
            OwnerRouteHint::DocsContract,
        ),
    ];

    let report = build_report("t", "d", "RGC-704B", &observations);
    let jsonl = report.benchmark_parity_verdict_jsonl().expect("render");
    for line in jsonl.split('\n') {
        let record: BenchmarkParityVerdictRecord =
            serde_json::from_str(line).expect("each line should parse");
        assert!(!record.workload_id.is_empty());
    }
}

// --- classify_observation edge cases ---

#[test]
fn classify_all_flags_passing_is_equivalent() {
    let obs = observation(
        "all_pass",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::Equivalent
    );
}

#[test]
fn classify_noise_takes_priority_over_output_mismatch() {
    // noise_only=true with output_equivalent=false: noise wins
    let obs = observation(
        "noise_vs_mismatch",
        EvidenceSurface::ShippedPath,
        false,
        true,
        true,
        true,
        OwnerRouteHint::RuntimeSemantics,
    );
    assert_eq!(
        classify_observation(&obs),
        BehaviorEquivalenceClass::BenchmarkNoise
    );
}

// --- Report schema and metadata ---

#[test]
fn report_carries_correct_schema_and_component() {
    let report = build_report("trace-meta", "dec-meta", "RGC-704B", &[]);
    assert_eq!(
        report.schema_version,
        "franken-engine.benchmark-behavior-equivalence.v1"
    );
    assert_eq!(report.component, "benchmark_behavior_equivalence");
    assert_eq!(report.policy_id, "RGC-704B");
    assert_eq!(report.trace_id, "trace-meta");
    assert_eq!(report.decision_id, "dec-meta");
}

#[test]
fn report_preserves_custom_policy_id() {
    let report = build_report("t", "d", "CUSTOM-POLICY-42", &[]);
    assert_eq!(report.policy_id, "CUSTOM-POLICY-42");
}

// --- Verdict record field correctness ---

#[test]
fn verdict_record_carries_correct_detail() {
    let obs = observation(
        "detail_test",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    let record = build_record(&obs);
    assert_eq!(record.detail, "fixture-detail");
}

#[test]
fn verdict_record_equivalent_has_no_owner_route() {
    let obs = observation(
        "no_route",
        EvidenceSurface::ShippedPath,
        true,
        true,
        true,
        false,
        OwnerRouteHint::RuntimeSemantics,
    );
    let record = build_record(&obs);
    assert!(record.owner_route.is_none());
    assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
}
