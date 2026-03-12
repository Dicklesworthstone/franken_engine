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
