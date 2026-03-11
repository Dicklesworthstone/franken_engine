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
