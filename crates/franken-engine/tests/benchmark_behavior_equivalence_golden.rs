use frankenengine_engine::benchmark_behavior_equivalence::{
    BehaviorEquivalenceObservation, EvidenceSurface, OwnerRouteHint, POLICY_ID, build_report,
};
use frankenengine_engine::benchmark_evidence_bundle::ParityTarget;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn observation(
    workload_id: &str,
    baseline: ParityTarget,
    surface: EvidenceSurface,
    owner_hint: OwnerRouteHint,
) -> BehaviorEquivalenceObservation {
    BehaviorEquivalenceObservation::new(workload_id, baseline, surface, owner_hint)
}

#[test]
fn build_report_golden_snapshot() {
    let epoch = SecurityEpoch::from_raw(704);
    let observations = vec![
        observation(
            "zeta_shipped_path_drift",
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        )
        .with_output_equivalence(false)
        .with_detail("shipped path output diverged from the node baseline")
        .with_minimized_repro_command("frankenctl bench --workload zeta_shipped_path_drift --min"),
        observation(
            "alpha_module_unsupported",
            ParityTarget::Bun,
            EvidenceSurface::LibraryOnly,
            OwnerRouteHint::ModuleInterop,
        )
        .with_feature_supported(false)
        .with_detail("module loader edge case is not implemented in the bun parity lane"),
        observation(
            "gamma_equivalent_library",
            ParityTarget::Deno,
            EvidenceSurface::LibraryOnly,
            OwnerRouteHint::BenchmarkCorpus,
        )
        .with_detail("library-only parity evidence retained for corpus monitoring"),
        observation(
            "beta_infra_failure",
            ParityTarget::V8Isolate,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::TypeScriptNormalization,
        )
        .with_infra_ok(false)
        .with_detail("runner failed before collecting a comparable output"),
    ];

    let report = build_report(
        format!("trace-rgc-704b-epoch-{}", epoch.as_u64()),
        format!("decision-rgc-704b-epoch-{}", epoch.as_u64()),
        POLICY_ID,
        &observations,
    );
    let actual =
        serde_json::to_string_pretty(&report).expect("report JSON should serialize") + "\n";

    insta::assert_snapshot!("build_report_golden_snapshot", actual);
}
