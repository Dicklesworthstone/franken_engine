#![forbid(unsafe_code)]

use frankenengine_engine::module_compatibility_matrix::{
    CompatibilityMatrixEntry, CompatibilityMode, DivergencePolicy, ExplicitShim,
    ModuleCompatibilityMatrix, ModuleFeature, ReferenceRuntime,
};

fn base_entry(case_id: &str) -> CompatibilityMatrixEntry {
    CompatibilityMatrixEntry {
        case_id: case_id.to_string(),
        feature: ModuleFeature::Esm,
        scenario: "integration test scenario".to_string(),
        node_behavior: "ok".to_string(),
        bun_behavior: "ok".to_string(),
        franken_native_behavior: "ok".to_string(),
        franken_node_compat_behavior: "ok".to_string(),
        franken_bun_compat_behavior: "ok".to_string(),
        explicit_shims: Vec::new(),
        lockstep_case_refs: vec!["lockstep/integ/ref".to_string()],
        test262_refs: vec!["language/module-code/integ.js".to_string()],
        divergence: None,
    }
}

fn make_shim(shim_id: &str, mode: CompatibilityMode) -> ExplicitShim {
    ExplicitShim {
        shim_id: shim_id.to_string(),
        mode,
        description: "shim description".to_string(),
        removable: true,
        test_case_ref: "lockstep/integ/ref".to_string(),
    }
}

fn divergence_for(runtimes: Vec<ReferenceRuntime>, waiver: &str) -> DivergencePolicy {
    DivergencePolicy {
        diverges_from: runtimes,
        reason: "integration test divergence".to_string(),
        impact: "low".to_string(),
        waiver_id: waiver.to_string(),
        migration_guidance: "use compat mode".to_string(),
    }
}

fn matrix_with(entries: Vec<CompatibilityMatrixEntry>) -> ModuleCompatibilityMatrix {
    ModuleCompatibilityMatrix::from_entries("1.0.0", entries).unwrap()
}

#[test]
fn canonical_hash_metamorphic_invariant_under_normalizing_input_transformations() {
    let mut alpha = base_entry("alpha");
    alpha.lockstep_case_refs = vec!["lockstep/a".to_string(), "lockstep/b".to_string()];
    alpha.test262_refs = vec!["language/a.js".to_string(), "language/b.js".to_string()];
    alpha.explicit_shims = vec![
        make_shim("shim-alpha-node", CompatibilityMode::NodeCompat),
        make_shim("shim-alpha-bun", CompatibilityMode::BunCompat),
    ];
    alpha.divergence = Some(divergence_for(
        vec![ReferenceRuntime::Node, ReferenceRuntime::Bun],
        "waiver-alpha",
    ));

    let mut beta = base_entry("beta");
    beta.feature = ModuleFeature::Cjs;
    beta.lockstep_case_refs = vec!["lockstep/c".to_string()];
    beta.test262_refs = vec!["built-ins/c.js".to_string()];

    let canonical = matrix_with(vec![alpha.clone(), beta.clone()]);

    let mut alpha_transformed = alpha;
    alpha_transformed.case_id = " alpha ".to_string();
    alpha_transformed.scenario = " integration test scenario ".to_string();
    alpha_transformed.lockstep_case_refs = vec![
        " lockstep/b ".to_string(),
        "lockstep/a".to_string(),
        "lockstep/b".to_string(),
    ];
    alpha_transformed.test262_refs = vec![
        "language/b.js".to_string(),
        " language/a.js ".to_string(),
        "language/b.js".to_string(),
    ];
    alpha_transformed.explicit_shims = vec![
        ExplicitShim {
            shim_id: " shim-alpha-bun ".to_string(),
            mode: CompatibilityMode::BunCompat,
            description: " shim description ".to_string(),
            removable: true,
            test_case_ref: " lockstep/integ/ref ".to_string(),
        },
        ExplicitShim {
            shim_id: " shim-alpha-node ".to_string(),
            mode: CompatibilityMode::NodeCompat,
            description: " shim description ".to_string(),
            removable: true,
            test_case_ref: " lockstep/integ/ref ".to_string(),
        },
    ];
    alpha_transformed.divergence = Some(DivergencePolicy {
        diverges_from: vec![
            ReferenceRuntime::Bun,
            ReferenceRuntime::Node,
            ReferenceRuntime::Bun,
        ],
        reason: " integration test divergence ".to_string(),
        impact: " low ".to_string(),
        waiver_id: " waiver-alpha ".to_string(),
        migration_guidance: " use compat mode ".to_string(),
    });

    let mut beta_transformed = beta;
    beta_transformed.case_id = " beta ".to_string();
    beta_transformed.lockstep_case_refs = vec![
        "lockstep/c".to_string(),
        " lockstep/c ".to_string(),
        "".to_string(),
    ];
    beta_transformed.test262_refs =
        vec![" built-ins/c.js ".to_string(), "built-ins/c.js".to_string()];

    let transformed = matrix_with(vec![beta_transformed, alpha_transformed]);

    assert_eq!(canonical.canonical_hash(), transformed.canonical_hash());
    assert_eq!(canonical.canonical_bytes(), transformed.canonical_bytes());
}
