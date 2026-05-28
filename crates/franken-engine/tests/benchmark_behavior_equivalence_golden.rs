use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::benchmark_behavior_equivalence::{
    BehaviorEquivalenceObservation, EvidenceSurface, OwnerRouteHint, POLICY_ID, build_report,
};
use frankenengine_engine::benchmark_evidence_bundle::ParityTarget;
use frankenengine_engine::security_epoch::SecurityEpoch;

const GOLDEN_RELATIVE_PATH: &str =
    "tests/golden/benchmark_behavior_equivalence_build_report_expected.json";

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_RELATIVE_PATH)
}

fn update_golden() -> bool {
    std::env::var_os("UPDATE_GOLDENS").is_some()
}

fn assert_golden_json(actual: &str) {
    let path = golden_path();
    if update_golden() {
        fs::create_dir_all(
            path.parent()
                .expect("golden path must have a parent directory"),
        )
        .expect("golden directory should be writable");
        fs::write(&path, actual).expect("golden snapshot should be writable");
        return;
    }

    let expected = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "failed to read golden snapshot {}: {err}; rerun with UPDATE_GOLDENS=1",
            path.display()
        )
    });
    assert_eq!(
        expected,
        actual,
        "golden snapshot drifted: {}",
        path.display()
    );
}

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

    assert_golden_json(&actual);
}
