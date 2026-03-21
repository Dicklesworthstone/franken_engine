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

use std::{collections::BTreeSet, fs, path::PathBuf};

use frankenengine_engine::feature_parity_tracker::{
    FeatureParityTracker, TrackerContext, WaiverRecord,
};
use frankenengine_engine::module_compatibility_matrix::{
    CompatibilityContext, CompatibilityMatrixErrorCode, CompatibilityMode,
    CompatibilityObservation, CompatibilityRuntime, DEFAULT_MATRIX_JSON, ModuleCompatibilityMatrix,
    ModuleFeature,
};

fn context() -> CompatibilityContext {
    CompatibilityContext::new(
        "trace-modcompat-integration",
        "decision-modcompat-integration",
        "policy-modcompat-integration",
    )
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn default_matrix_is_machine_readable_and_validates_with_declared_waivers() {
    serde_json::from_str::<serde_json::Value>(DEFAULT_MATRIX_JSON)
        .expect("default matrix json must parse");

    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let waivers = matrix.required_waiver_ids();
    assert!(!waivers.is_empty(), "expected at least one required waiver");

    matrix
        .validate_with_waivers(&waivers, &context())
        .expect("default matrix should validate with declared waivers");

    let event = matrix
        .events()
        .last()
        .expect("validation should emit at least one event");
    assert_eq!(event.component, "module_compatibility_matrix");
    assert_eq!(event.trace_id, "trace-modcompat-integration");
    assert_eq!(event.decision_id, "decision-modcompat-integration");
    assert_eq!(event.policy_id, "policy-modcompat-integration");
    assert!(!event.event.is_empty());
    assert!(!event.outcome.is_empty());
    assert!(!event.error_code.is_empty());
}

#[test]
fn default_matrix_covers_required_feature_categories() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let features = matrix
        .entries()
        .into_iter()
        .map(|entry| entry.feature)
        .collect::<BTreeSet<_>>();

    assert!(features.contains(&ModuleFeature::Esm));
    assert!(features.contains(&ModuleFeature::Cjs));
    assert!(features.contains(&ModuleFeature::DualMode));
    assert!(features.contains(&ModuleFeature::ConditionalExports));
    assert!(features.contains(&ModuleFeature::PackageJsonFields));
}

#[test]
fn missing_waiver_fails_validation_with_stable_error_code() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let error = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect_err("expected missing-waiver validation error");

    assert_eq!(error.code, CompatibilityMatrixErrorCode::MissingWaiver);
    let event = error.event.expect("validation errors should include event");
    assert_eq!(
        event.error_code,
        CompatibilityMatrixErrorCode::MissingWaiver.stable_code()
    );
    assert_eq!(event.component, "module_compatibility_matrix");
}

#[test]
fn observation_evaluation_supports_match_and_mismatch_paths() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");
    let waivers = matrix.required_waiver_ids();
    matrix
        .validate_with_waivers(&waivers, &context())
        .expect("matrix validation must pass before observation checks");

    let matched = matrix
        .evaluate_observation(
            &CompatibilityObservation::new(
                "esm-import-cjs-default",
                CompatibilityRuntime::FrankenEngine,
                CompatibilityMode::Native,
                "namespace_default_projection",
            ),
            &context(),
        )
        .expect("expected observation match");
    assert!(matched.matched);
    assert_eq!(matched.event.outcome, "allow");
    assert_eq!(matched.event.error_code, "none");

    let mismatch = matrix
        .evaluate_observation(
            &CompatibilityObservation::new(
                "cjs-require-esm",
                CompatibilityRuntime::FrankenEngine,
                CompatibilityMode::Native,
                "unexpected_behavior",
            ),
            &context(),
        )
        .expect_err("expected mismatch error");
    assert_eq!(
        mismatch.code,
        CompatibilityMatrixErrorCode::ObservationMismatch
    );
}

#[test]
fn tracker_backed_validation_uses_registered_waiver_ids() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix");

    let mut tracker = FeatureParityTracker::new();
    let tracker_feature_id = tracker
        .features()
        .keys()
        .next()
        .cloned()
        .expect("tracker should have default features");
    let tracker_ctx = TrackerContext {
        trace_id: "trace-tracker".to_string(),
        decision_id: "decision-tracker".to_string(),
        policy_id: "policy-tracker".to_string(),
    };

    for waiver_id in matrix.required_waiver_ids() {
        tracker
            .register_waiver(
                WaiverRecord {
                    waiver_id,
                    feature_id: tracker_feature_id.clone(),
                    reason: "module edge divergence approved".to_string(),
                    approved_by: "ops".to_string(),
                    approved_at_ns: 10,
                    valid_until_ns: Some(20),
                    test262_exemptions: Vec::new(),
                    lockstep_exemptions: Vec::new(),
                    sealed: false,
                },
                &tracker_ctx,
            )
            .expect("waiver registration should succeed");
    }

    matrix
        .validate_against_tracker(&tracker, &context())
        .expect("tracker-backed validation should pass");
}

#[test]
fn canonical_hash_is_stable_across_reloads() {
    let a = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix a");
    let b = ModuleCompatibilityMatrix::from_default_json().expect("load default matrix b");
    assert_eq!(a.canonical_hash(), b.canonical_hash());
}

#[test]
fn module_interop_gate_script_surfaces_replay_and_trace_artifacts() {
    let path = repo_root().join("scripts/run_rgc_module_interop_verification_matrix.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    assert!(
        script.contains(
            "replay_command=\"RGC_MODULE_INTEROP_MATRIX_REPLAY_RUN_DIR=${run_dir} ./scripts/e2e/rgc_module_interop_verification_matrix_replay.sh\""
        ),
        "gate script must emit an exact-run-dir replay command for the current bundle"
    );
    assert!(
        script
            .contains("module_resolution_trace_path=\"${run_dir}/module_resolution_trace.jsonl\""),
        "gate script must define the module resolution trace artifact path"
    );
    assert!(
        script.contains("\"module_resolution_trace\": \"${module_resolution_trace_path}\""),
        "run manifest must publish the module resolution trace artifact path"
    );
    assert!(
        script.contains("cat ${commands_path}"),
        "operator verification must surface the commands artifact"
    );
    assert!(
        script.contains("cat ${module_resolution_trace_path}"),
        "operator verification must surface the module resolution trace artifact"
    );
    assert!(
        script.contains("rgc module interop verification matrix commands: ${commands_path}"),
        "gate script must print the commands artifact path"
    );
    assert!(
        script.contains(
            "rgc module interop verification matrix module resolution trace: ${module_resolution_trace_path}"
        ),
        "gate script must print the module resolution trace artifact path"
    );
}

#[test]
fn module_interop_replay_wrapper_requires_complete_bundle() {
    let path = repo_root().join("scripts/e2e/rgc_module_interop_verification_matrix_replay.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "module_resolution_trace.jsonl",
    ] {
        assert!(
            script.contains(required),
            "replay wrapper must require {required}"
        );
    }

    assert!(
        script.contains("latest_complete_run_dir()"),
        "replay wrapper must scan for the latest complete bundle"
    );
    assert!(
        script.contains("RGC_MODULE_INTEROP_MATRIX_REPLAY_RUN_DIR"),
        "replay wrapper must support exact-run-dir targeting for emitted bundles"
    );
    assert!(
        script.contains("explicit run directory is incomplete"),
        "replay wrapper must fail closed when an explicitly targeted run directory is incomplete"
    );
    assert!(
        script.contains("newest directory")
            && script.contains("is incomplete")
            && script.contains("complete run directory"),
        "replay wrapper must fail closed on incomplete artifact bundles"
    );
    assert!(
        script.contains("warn_about_failed_gate_replay_source()"),
        "replay wrapper must centralize failed-gate replay warnings in a dedicated helper"
    );
    assert!(
        script.contains("replay output reflects latest complete run directory"),
        "replay wrapper must warn when it falls back to an older complete run after a failed gate invocation"
    );
    assert!(
        script.contains("replay output reflects current run directory"),
        "replay wrapper must distinguish a failed gate that still produced the current complete run bundle"
    );
    assert!(
        script.contains("latest module resolution trace"),
        "replay wrapper must print the module resolution trace artifact"
    );
    assert!(
        script.contains("rgc_module_resolution_trace_contract_smoke.sh"),
        "replay wrapper must re-run the trace smoke contract"
    );
}

// ---------- context helper ----------

#[test]
fn context_sets_trace_fields() {
    let ctx = context();
    assert_eq!(ctx.trace_id, "trace-modcompat-integration");
    assert_eq!(ctx.decision_id, "decision-modcompat-integration");
    assert_eq!(ctx.policy_id, "policy-modcompat-integration");
}

// ---------- ModuleFeature ----------

#[test]
fn module_feature_serde_roundtrip() {
    for feature in [
        ModuleFeature::Esm,
        ModuleFeature::Cjs,
        ModuleFeature::DualMode,
        ModuleFeature::ConditionalExports,
        ModuleFeature::PackageJsonFields,
    ] {
        let json = serde_json::to_string(&feature).expect("serialize");
        let recovered: ModuleFeature = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, feature);
    }
}

#[test]
fn module_feature_as_str_is_nonempty() {
    for feature in [
        ModuleFeature::Esm,
        ModuleFeature::Cjs,
        ModuleFeature::DualMode,
        ModuleFeature::ConditionalExports,
        ModuleFeature::PackageJsonFields,
    ] {
        assert!(!feature.as_str().is_empty());
    }
}

// ---------- CompatibilityRuntime ----------

#[test]
fn compatibility_runtime_serde_roundtrip() {
    for runtime in [
        CompatibilityRuntime::FrankenEngine,
        CompatibilityRuntime::Node,
        CompatibilityRuntime::Bun,
    ] {
        let json = serde_json::to_string(&runtime).expect("serialize");
        let recovered: CompatibilityRuntime = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, runtime);
    }
}

#[test]
fn compatibility_runtime_as_str_is_nonempty() {
    for runtime in [
        CompatibilityRuntime::FrankenEngine,
        CompatibilityRuntime::Node,
        CompatibilityRuntime::Bun,
    ] {
        assert!(!runtime.as_str().is_empty());
    }
}

// ---------- CompatibilityMode ----------

#[test]
fn compatibility_mode_serde_roundtrip() {
    for mode in [
        CompatibilityMode::Native,
        CompatibilityMode::NodeCompat,
        CompatibilityMode::BunCompat,
    ] {
        let json = serde_json::to_string(&mode).expect("serialize");
        let recovered: CompatibilityMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, mode);
    }
}

#[test]
fn compatibility_mode_as_str_is_nonempty() {
    for mode in [
        CompatibilityMode::Native,
        CompatibilityMode::NodeCompat,
        CompatibilityMode::BunCompat,
    ] {
        assert!(!mode.as_str().is_empty());
    }
}

// ---------- CompatibilityMatrixErrorCode ----------

#[test]
fn error_code_stable_code_starts_with_fe() {
    for code in [
        CompatibilityMatrixErrorCode::MatrixParseError,
        CompatibilityMatrixErrorCode::DuplicateCaseId,
        CompatibilityMatrixErrorCode::CaseNotFound,
        CompatibilityMatrixErrorCode::HiddenShim,
        CompatibilityMatrixErrorCode::MissingWaiver,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance,
        CompatibilityMatrixErrorCode::InvalidMatrix,
        CompatibilityMatrixErrorCode::ObservationMismatch,
    ] {
        let stable = code.stable_code();
        assert!(
            stable.starts_with("FE-MODCOMP-"),
            "code {} does not start with FE-MODCOMP-",
            stable
        );
    }
}

#[test]
fn error_code_stable_codes_are_unique() {
    let codes = [
        CompatibilityMatrixErrorCode::MatrixParseError,
        CompatibilityMatrixErrorCode::DuplicateCaseId,
        CompatibilityMatrixErrorCode::CaseNotFound,
        CompatibilityMatrixErrorCode::HiddenShim,
        CompatibilityMatrixErrorCode::MissingWaiver,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance,
        CompatibilityMatrixErrorCode::InvalidMatrix,
        CompatibilityMatrixErrorCode::ObservationMismatch,
    ];
    let stable: BTreeSet<_> = codes.iter().map(|c| c.stable_code()).collect();
    assert_eq!(stable.len(), codes.len());
}

// ---------- DEFAULT_MATRIX_JSON ----------

#[test]
fn default_matrix_json_is_valid_json() {
    let value: serde_json::Value =
        serde_json::from_str(DEFAULT_MATRIX_JSON).expect("parse default matrix JSON");
    assert!(value.is_object());
}

// ---------- ModuleCompatibilityMatrix ----------

#[test]
fn matrix_entries_have_unique_case_ids() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    let entries = matrix.entries();
    let ids: BTreeSet<_> = entries.iter().map(|e| &e.case_id).collect();
    assert_eq!(ids.len(), entries.len());
}

#[test]
fn matrix_entry_lookup_by_case_id() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    let first_id = matrix.entries()[0].case_id.clone();
    let entry = matrix.entry(&first_id);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().case_id, first_id);
}

#[test]
fn matrix_entry_lookup_missing_returns_none() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    assert!(matrix.entry("nonexistent-case-id-xyz").is_none());
}

#[test]
fn matrix_to_json_pretty_roundtrips() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    let json = matrix.to_json_pretty().expect("serialize");
    assert!(json.contains("schema_version"));
    assert!(!json.is_empty());
}

#[test]
fn matrix_canonical_bytes_are_deterministic() {
    let a = ModuleCompatibilityMatrix::from_default_json().expect("load a");
    let b = ModuleCompatibilityMatrix::from_default_json().expect("load b");
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
}

// ---------- CompatibilityObservation ----------

#[test]
fn compatibility_observation_new_sets_fields() {
    let obs = CompatibilityObservation::new(
        "test-case",
        CompatibilityRuntime::Node,
        CompatibilityMode::NodeCompat,
        "expected_behavior",
    );
    assert_eq!(obs.case_id, "test-case");
    assert_eq!(obs.runtime, CompatibilityRuntime::Node);
    assert_eq!(obs.mode, CompatibilityMode::NodeCompat);
    assert_eq!(obs.observed_behavior, "expected_behavior");
}

// ---------- FeatureParityTracker ----------

#[test]
fn tracker_has_default_features() {
    let tracker = FeatureParityTracker::new();
    assert!(!tracker.features().is_empty());
}

// ---------- WaiverRecord ----------

#[test]
fn waiver_record_serde_roundtrip() {
    let waiver = WaiverRecord {
        waiver_id: "waiver-test".to_string(),
        feature_id: "feature-test".to_string(),
        reason: "test reason".to_string(),
        approved_by: "ops".to_string(),
        approved_at_ns: 100,
        valid_until_ns: Some(200),
        test262_exemptions: Vec::new(),
        lockstep_exemptions: Vec::new(),
        sealed: false,
    };
    let json = serde_json::to_string(&waiver).expect("serialize");
    let recovered: WaiverRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.waiver_id, "waiver-test");
    assert_eq!(recovered.valid_until_ns, Some(200));
}

// ---------- DEFAULT_MATRIX_JSON has schema_version ----------

#[test]
fn default_matrix_json_has_schema_version_field() {
    let value: serde_json::Value =
        serde_json::from_str(DEFAULT_MATRIX_JSON).expect("parse default matrix JSON");
    let sv = value["schema_version"]
        .as_str()
        .expect("schema_version must be string");
    assert!(!sv.trim().is_empty());
}

// ---------- CompatibilityMatrixErrorCode serde roundtrip ----------

#[test]
fn error_code_serde_roundtrip() {
    for code in [
        CompatibilityMatrixErrorCode::MatrixParseError,
        CompatibilityMatrixErrorCode::DuplicateCaseId,
        CompatibilityMatrixErrorCode::CaseNotFound,
        CompatibilityMatrixErrorCode::HiddenShim,
        CompatibilityMatrixErrorCode::MissingWaiver,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance,
        CompatibilityMatrixErrorCode::InvalidMatrix,
        CompatibilityMatrixErrorCode::ObservationMismatch,
    ] {
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: CompatibilityMatrixErrorCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, code);
    }
}

// ---------- matrix entries all have nonempty case_id ----------

#[test]
fn matrix_entries_all_have_nonempty_case_id() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    for entry in matrix.entries() {
        assert!(
            !entry.case_id.trim().is_empty(),
            "every matrix entry must have a non-empty case_id"
        );
    }
}

// ---------- matrix canonical_hash is nonempty ----------

#[test]
fn matrix_canonical_hash_is_stable() {
    let a = ModuleCompatibilityMatrix::from_default_json().expect("load a");
    let b = ModuleCompatibilityMatrix::from_default_json().expect("load b");
    let hash_a = serde_json::to_string(&a.canonical_hash()).expect("serialize hash a");
    let hash_b = serde_json::to_string(&b.canonical_hash()).expect("serialize hash b");
    assert_eq!(hash_a, hash_b, "canonical_hash must be stable across loads");
    assert!(!hash_a.is_empty());
}

// ---------- CompatibilityContext serde roundtrip ----------

#[test]
fn compatibility_context_serde_roundtrip() {
    let ctx = CompatibilityContext::new("trace-1", "decision-1", "policy-1");
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: CompatibilityContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-1");
    assert_eq!(recovered.decision_id, "decision-1");
    assert_eq!(recovered.policy_id, "policy-1");
}

// ---------- matrix required_waiver_ids are nonempty strings ----------

#[test]
fn matrix_required_waiver_ids_are_nonempty_strings() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    let waivers = matrix.required_waiver_ids();
    for waiver_id in &waivers {
        assert!(!waiver_id.trim().is_empty(), "waiver_id must be non-empty");
    }
}

// ---------- matrix entries have at least one entry ----------

#[test]
fn matrix_has_at_least_one_entry() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    assert!(!matrix.entries().is_empty(), "matrix must have entries");
}

#[test]
fn default_matrix_json_is_nonempty() {
    assert!(
        !DEFAULT_MATRIX_JSON.is_empty(),
        "DEFAULT_MATRIX_JSON constant must not be empty"
    );
}

#[test]
fn compatibility_context_debug_is_nonempty() {
    let ctx = context();
    assert!(!format!("{ctx:?}").is_empty());
}

#[test]
fn waiver_record_debug_is_nonempty() {
    let waiver = WaiverRecord {
        waiver_id: "w1".to_string(),
        feature_id: "f1".to_string(),
        reason: "test".to_string(),
        approved_by: "ops".to_string(),
        approved_at_ns: 100,
        valid_until_ns: None,
        test262_exemptions: Vec::new(),
        lockstep_exemptions: Vec::new(),
        sealed: false,
    };
    assert!(!format!("{waiver:?}").is_empty());
}

// ======================== Enrichment: PearlTower 2026-03-12 ========================

use std::collections::BTreeMap;

use frankenengine_engine::module_compatibility_matrix::{
    COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION, CompatibilityEvent, CompatibilityMatrixEntry,
    CompatibilityMatrixError, CompatibilityObservationOutcome, CompatibilityScenarioReport,
    DivergenceCategory, DivergencePolicy, ExplicitShim, ReferenceRuntime,
};

// ---------- helper: build a valid entry for integration tests ----------

fn valid_entry_integ(case_id: &str) -> CompatibilityMatrixEntry {
    CompatibilityMatrixEntry {
        case_id: case_id.to_string(),
        feature: ModuleFeature::Esm,
        scenario: "test scenario".to_string(),
        node_behavior: "ok".to_string(),
        bun_behavior: "ok".to_string(),
        franken_native_behavior: "ok".to_string(),
        franken_node_compat_behavior: "ok".to_string(),
        franken_bun_compat_behavior: "ok".to_string(),
        explicit_shims: Vec::new(),
        lockstep_case_refs: vec!["lockstep/ref".to_string()],
        test262_refs: vec!["test262/ref.js".to_string()],
        divergence: None,
    }
}

fn valid_shim_integ(mode: CompatibilityMode) -> ExplicitShim {
    ExplicitShim {
        shim_id: "shim-integ".to_string(),
        mode,
        description: "integration test shim".to_string(),
        removable: true,
        test_case_ref: "test/ref-integ.js".to_string(),
    }
}

// ---------- ReferenceRuntime serde roundtrip ----------

#[test]
fn reference_runtime_serde_roundtrip() {
    for variant in [ReferenceRuntime::Node, ReferenceRuntime::Bun] {
        let json = serde_json::to_string(&variant).expect("serialize");
        let recovered: ReferenceRuntime = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, variant);
    }
}

// ---------- ReferenceRuntime as_str exact values ----------

#[test]
fn reference_runtime_as_str_exact_values() {
    assert_eq!(ReferenceRuntime::Node.as_str(), "node");
    assert_eq!(ReferenceRuntime::Bun.as_str(), "bun");
}

#[test]
fn reference_runtime_as_str_nonempty() {
    for variant in [ReferenceRuntime::Node, ReferenceRuntime::Bun] {
        assert!(!variant.as_str().is_empty());
    }
}

// ---------- ReferenceRuntime ordering ----------

#[test]
fn reference_runtime_ord() {
    assert!(ReferenceRuntime::Node < ReferenceRuntime::Bun);
}

// ---------- DivergenceCategory serde roundtrip ----------

#[test]
fn divergence_category_serde_roundtrip() {
    for variant in [
        DivergenceCategory::EngineBug,
        DivergenceCategory::IntentionalImprovement,
        DivergenceCategory::CompatibilityDebt,
        DivergenceCategory::EcosystemAmbiguity,
        DivergenceCategory::ReferenceRuntimeBug,
    ] {
        let json = serde_json::to_string(&variant).expect("serialize");
        let recovered: DivergenceCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, variant);
    }
}

// ---------- DivergenceCategory as_str exact values ----------

#[test]
fn divergence_category_as_str_exact_values() {
    assert_eq!(DivergenceCategory::EngineBug.as_str(), "engine_bug");
    assert_eq!(
        DivergenceCategory::IntentionalImprovement.as_str(),
        "intentional_improvement"
    );
    assert_eq!(
        DivergenceCategory::CompatibilityDebt.as_str(),
        "compatibility_debt"
    );
    assert_eq!(
        DivergenceCategory::EcosystemAmbiguity.as_str(),
        "ecosystem_ambiguity"
    );
    assert_eq!(
        DivergenceCategory::ReferenceRuntimeBug.as_str(),
        "reference_runtime_bug"
    );
}

#[test]
fn divergence_category_as_str_nonempty() {
    for variant in [
        DivergenceCategory::EngineBug,
        DivergenceCategory::IntentionalImprovement,
        DivergenceCategory::CompatibilityDebt,
        DivergenceCategory::EcosystemAmbiguity,
        DivergenceCategory::ReferenceRuntimeBug,
    ] {
        assert!(!variant.as_str().is_empty());
    }
}

// ---------- DivergenceCategory ordering ----------

#[test]
fn divergence_category_ord() {
    assert!(DivergenceCategory::EngineBug < DivergenceCategory::IntentionalImprovement);
    assert!(DivergenceCategory::IntentionalImprovement < DivergenceCategory::CompatibilityDebt);
    assert!(DivergenceCategory::CompatibilityDebt < DivergenceCategory::EcosystemAmbiguity);
    assert!(DivergenceCategory::EcosystemAmbiguity < DivergenceCategory::ReferenceRuntimeBug);
}

// ---------- ExplicitShim serde roundtrip ----------

#[test]
fn explicit_shim_serde_roundtrip() {
    let shim = ExplicitShim {
        shim_id: "shim-serde".to_string(),
        mode: CompatibilityMode::NodeCompat,
        description: "test shim for serde".to_string(),
        removable: true,
        test_case_ref: "test/serde-ref.js".to_string(),
    };
    let json = serde_json::to_string(&shim).expect("serialize");
    let recovered: ExplicitShim = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, shim);
}

#[test]
fn explicit_shim_serde_all_modes() {
    for mode in [
        CompatibilityMode::Native,
        CompatibilityMode::NodeCompat,
        CompatibilityMode::BunCompat,
    ] {
        let shim = valid_shim_integ(mode);
        let json = serde_json::to_string(&shim).expect("serialize");
        let recovered: ExplicitShim = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered.mode, mode);
    }
}

// ---------- DivergencePolicy serde roundtrip ----------

#[test]
fn divergence_policy_serde_roundtrip() {
    let policy = DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node, ReferenceRuntime::Bun],
        reason: "ecosystem split".to_string(),
        impact: "moderate".to_string(),
        waiver_id: "w-policy".to_string(),
        migration_guidance: "use compat shim".to_string(),
    };
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: DivergencePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

#[test]
fn divergence_policy_with_single_runtime() {
    let policy = DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Bun],
        reason: "bun specific".to_string(),
        impact: "low".to_string(),
        waiver_id: "w-bun".to_string(),
        migration_guidance: "no action needed".to_string(),
    };
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: DivergencePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.diverges_from.len(), 1);
    assert_eq!(recovered.diverges_from[0], ReferenceRuntime::Bun);
}

// ---------- CompatibilityMatrixEntry serde roundtrip ----------

#[test]
fn compatibility_matrix_entry_serde_roundtrip() {
    let entry = valid_entry_integ("case-serde-integ");
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: CompatibilityMatrixEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, entry);
}

#[test]
fn compatibility_matrix_entry_with_shims_serde_roundtrip() {
    let mut entry = valid_entry_integ("case-with-shims");
    entry.explicit_shims = vec![
        valid_shim_integ(CompatibilityMode::NodeCompat),
        valid_shim_integ(CompatibilityMode::BunCompat),
    ];
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: CompatibilityMatrixEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.explicit_shims.len(), 2);
}

#[test]
fn compatibility_matrix_entry_with_divergence_serde_roundtrip() {
    let mut entry = valid_entry_integ("case-with-div");
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "test reason".to_string(),
        impact: "test impact".to_string(),
        waiver_id: "w-test".to_string(),
        migration_guidance: "test guidance".to_string(),
    });
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: CompatibilityMatrixEntry = serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.divergence.is_some());
}

// ---------- CompatibilityEvent serde roundtrip ----------

#[test]
fn compatibility_event_serde_roundtrip() {
    let event = CompatibilityEvent {
        seq: 42,
        trace_id: "trace-event".to_string(),
        decision_id: "decision-event".to_string(),
        policy_id: "policy-event".to_string(),
        component: "module_compatibility_matrix".to_string(),
        event: "compatibility_entry_validated".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
        case_id: "case-event".to_string(),
        runtime: "franken_engine".to_string(),
        mode: "native".to_string(),
        detail: "test detail".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: CompatibilityEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
    assert_eq!(recovered.seq, 42);
}

#[test]
fn compatibility_event_debug_is_nonempty() {
    let event = CompatibilityEvent {
        seq: 0,
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: "ec".to_string(),
        case_id: "ci".to_string(),
        runtime: "r".to_string(),
        mode: "m".to_string(),
        detail: "det".to_string(),
    };
    assert!(!format!("{event:?}").is_empty());
}

// ---------- CompatibilityMatrixError serde roundtrip ----------

#[test]
fn compatibility_matrix_error_serde_roundtrip_without_event() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::CaseNotFound,
        message: "case missing".to_string(),
        event: None,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: CompatibilityMatrixError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
    assert!(recovered.event.is_none());
}

#[test]
fn compatibility_matrix_error_serde_roundtrip_with_event() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::ObservationMismatch,
        message: "behavior mismatch".to_string(),
        event: Some(CompatibilityEvent {
            seq: 7,
            trace_id: "trace-err".to_string(),
            decision_id: "decision-err".to_string(),
            policy_id: "policy-err".to_string(),
            component: "module_compatibility_matrix".to_string(),
            event: "compatibility_observation".to_string(),
            outcome: "deny".to_string(),
            error_code: "FE-MODCOMP-0008".to_string(),
            case_id: "case-err".to_string(),
            runtime: "franken_engine".to_string(),
            mode: "native".to_string(),
            detail: "mismatch detail".to_string(),
        }),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: CompatibilityMatrixError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
    assert!(recovered.event.is_some());
}

// ---------- CompatibilityMatrixError Display ----------

#[test]
fn compatibility_matrix_error_display_without_event() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::InvalidMatrix,
        message: "bad matrix".to_string(),
        event: None,
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-MODCOMP-0007"), "display: {msg}");
    assert!(msg.contains("bad matrix"), "display: {msg}");
}

#[test]
fn compatibility_matrix_error_display_with_event_contains_trace_fields() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::CaseNotFound,
        message: "not found".to_string(),
        event: Some(CompatibilityEvent {
            seq: 0,
            trace_id: "trace-display".to_string(),
            decision_id: "decision-display".to_string(),
            policy_id: "policy-display".to_string(),
            component: "module_compatibility_matrix".to_string(),
            event: "lookup".to_string(),
            outcome: "deny".to_string(),
            error_code: "FE-MODCOMP-0003".to_string(),
            case_id: "c1".to_string(),
            runtime: "franken_engine".to_string(),
            mode: "native".to_string(),
            detail: "missing".to_string(),
        }),
    };
    let msg = err.to_string();
    assert!(msg.contains("trace-display"), "display: {msg}");
    assert!(msg.contains("decision-display"), "display: {msg}");
    assert!(msg.contains("policy-display"), "display: {msg}");
    assert!(msg.contains("FE-MODCOMP-0003"), "display: {msg}");
}

#[test]
fn compatibility_matrix_error_is_std_error() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::InvalidMatrix,
        message: "test error".to_string(),
        event: None,
    };
    let _: &dyn std::error::Error = &err;
}

// ---------- CompatibilityObservation serde roundtrip ----------

#[test]
fn compatibility_observation_serde_roundtrip() {
    let obs = CompatibilityObservation::new(
        "case-obs-serde",
        CompatibilityRuntime::Bun,
        CompatibilityMode::BunCompat,
        "expected-bun",
    );
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: CompatibilityObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.case_id, "case-obs-serde");
    assert_eq!(recovered.runtime, CompatibilityRuntime::Bun);
    assert_eq!(recovered.mode, CompatibilityMode::BunCompat);
    assert_eq!(recovered.observed_behavior, "expected-bun");
}

// ---------- CompatibilityObservationOutcome serde roundtrip ----------

#[test]
fn compatibility_observation_outcome_serde_roundtrip() {
    let outcome = CompatibilityObservationOutcome {
        case_id: "case-outcome".to_string(),
        runtime: CompatibilityRuntime::FrankenEngine,
        mode: CompatibilityMode::Native,
        observed_behavior: "ok".to_string(),
        expected_behavior: "ok".to_string(),
        matched: true,
        divergence: None,
        divergence_category: None,
        actionable_guidance: None,
        event: CompatibilityEvent {
            seq: 0,
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "module_compatibility_matrix".to_string(),
            event: "compatibility_observation".to_string(),
            outcome: "allow".to_string(),
            error_code: "none".to_string(),
            case_id: "case-outcome".to_string(),
            runtime: "franken_engine".to_string(),
            mode: "native".to_string(),
            detail: "matched".to_string(),
        },
    };
    let json = serde_json::to_string(&outcome).expect("serialize");
    let recovered: CompatibilityObservationOutcome =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.case_id, "case-outcome");
    assert!(recovered.matched);
    assert!(recovered.divergence.is_none());
}

#[test]
fn compatibility_observation_outcome_with_divergence_serde_roundtrip() {
    let outcome = CompatibilityObservationOutcome {
        case_id: "case-div-outcome".to_string(),
        runtime: CompatibilityRuntime::FrankenEngine,
        mode: CompatibilityMode::Native,
        observed_behavior: "strict".to_string(),
        expected_behavior: "strict".to_string(),
        matched: true,
        divergence: Some(DivergencePolicy {
            diverges_from: vec![ReferenceRuntime::Node],
            reason: "strict mode".to_string(),
            impact: "low".to_string(),
            waiver_id: "w-div-out".to_string(),
            migration_guidance: "use compat".to_string(),
        }),
        divergence_category: Some(DivergenceCategory::IntentionalImprovement),
        actionable_guidance: Some("guidance text".to_string()),
        event: CompatibilityEvent {
            seq: 1,
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "module_compatibility_matrix".to_string(),
            event: "compatibility_observation".to_string(),
            outcome: "allow".to_string(),
            error_code: "none".to_string(),
            case_id: "case-div-outcome".to_string(),
            runtime: "franken_engine".to_string(),
            mode: "native".to_string(),
            detail: "matched with divergence".to_string(),
        },
    };
    let json = serde_json::to_string(&outcome).expect("serialize");
    let recovered: CompatibilityObservationOutcome =
        serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.divergence.is_some());
    assert_eq!(
        recovered.divergence_category,
        Some(DivergenceCategory::IntentionalImprovement)
    );
    assert!(recovered.actionable_guidance.is_some());
}

// ---------- CompatibilityScenarioReport serde roundtrip ----------

#[test]
fn compatibility_scenario_report_serde_roundtrip() {
    let report = CompatibilityScenarioReport {
        schema_version: COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION.to_string(),
        scenario_id: "scenario-serde".to_string(),
        trace_id: "trace-report".to_string(),
        decision_id: "decision-report".to_string(),
        policy_id: "policy-report".to_string(),
        generated_at_unix_ms: 1_700_000_000_000,
        total_observations: 2,
        matched_observations: 2,
        divergence_category_counts: BTreeMap::new(),
        actionable_guidance: BTreeMap::new(),
        outcomes: Vec::new(),
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: CompatibilityScenarioReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.scenario_id, "scenario-serde");
    assert_eq!(recovered.total_observations, 2);
    assert_eq!(recovered.matched_observations, 2);
}

#[test]
fn compatibility_scenario_report_schema_version_constant_nonempty() {
    assert!(!COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION.is_empty());
    assert!(COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION.contains("v1"));
}

// ---------- ModuleFeature as_str exact values ----------

#[test]
fn module_feature_as_str_exact_values() {
    assert_eq!(ModuleFeature::Esm.as_str(), "esm");
    assert_eq!(ModuleFeature::Cjs.as_str(), "cjs");
    assert_eq!(ModuleFeature::DualMode.as_str(), "dual_mode");
    assert_eq!(
        ModuleFeature::ConditionalExports.as_str(),
        "conditional_exports"
    );
    assert_eq!(
        ModuleFeature::PackageJsonFields.as_str(),
        "package_json_fields"
    );
}

// ---------- CompatibilityRuntime as_str exact values ----------

#[test]
fn compatibility_runtime_as_str_exact_values() {
    assert_eq!(
        CompatibilityRuntime::FrankenEngine.as_str(),
        "franken_engine"
    );
    assert_eq!(CompatibilityRuntime::Node.as_str(), "node");
    assert_eq!(CompatibilityRuntime::Bun.as_str(), "bun");
}

// ---------- CompatibilityMode as_str exact values ----------

#[test]
fn compatibility_mode_as_str_exact_values() {
    assert_eq!(CompatibilityMode::Native.as_str(), "native");
    assert_eq!(CompatibilityMode::NodeCompat.as_str(), "node_compat");
    assert_eq!(CompatibilityMode::BunCompat.as_str(), "bun_compat");
}

// ---------- CompatibilityMatrixErrorCode stable_code exact values ----------

#[test]
fn error_code_stable_code_exact_values() {
    assert_eq!(
        CompatibilityMatrixErrorCode::MatrixParseError.stable_code(),
        "FE-MODCOMP-0001"
    );
    assert_eq!(
        CompatibilityMatrixErrorCode::DuplicateCaseId.stable_code(),
        "FE-MODCOMP-0002"
    );
    assert_eq!(
        CompatibilityMatrixErrorCode::CaseNotFound.stable_code(),
        "FE-MODCOMP-0003"
    );
    assert_eq!(
        CompatibilityMatrixErrorCode::HiddenShim.stable_code(),
        "FE-MODCOMP-0004"
    );
    assert_eq!(
        CompatibilityMatrixErrorCode::MissingWaiver.stable_code(),
        "FE-MODCOMP-0005"
    );
    assert_eq!(
        CompatibilityMatrixErrorCode::MissingMigrationGuidance.stable_code(),
        "FE-MODCOMP-0006"
    );
    assert_eq!(
        CompatibilityMatrixErrorCode::InvalidMatrix.stable_code(),
        "FE-MODCOMP-0007"
    );
    assert_eq!(
        CompatibilityMatrixErrorCode::ObservationMismatch.stable_code(),
        "FE-MODCOMP-0008"
    );
}

// ---------- Enum ordering ----------

#[test]
fn module_feature_ord() {
    assert!(ModuleFeature::Esm < ModuleFeature::Cjs);
    assert!(ModuleFeature::Cjs < ModuleFeature::DualMode);
    assert!(ModuleFeature::DualMode < ModuleFeature::ConditionalExports);
    assert!(ModuleFeature::ConditionalExports < ModuleFeature::PackageJsonFields);
}

#[test]
fn compatibility_runtime_ord() {
    assert!(CompatibilityRuntime::FrankenEngine < CompatibilityRuntime::Node);
    assert!(CompatibilityRuntime::Node < CompatibilityRuntime::Bun);
}

#[test]
fn compatibility_mode_ord() {
    assert!(CompatibilityMode::Native < CompatibilityMode::NodeCompat);
    assert!(CompatibilityMode::NodeCompat < CompatibilityMode::BunCompat);
}

// ---------- ModuleCompatibilityMatrix Default impl ----------

#[test]
fn matrix_default_impl_matches_from_default_json() {
    let default_matrix = ModuleCompatibilityMatrix::default();
    let explicit = ModuleCompatibilityMatrix::from_default_json().expect("load");
    assert_eq!(default_matrix.canonical_hash(), explicit.canonical_hash());
}

// ---------- from_entries: empty schema version ----------

#[test]
fn from_entries_empty_schema_version_fails() {
    let err = ModuleCompatibilityMatrix::from_entries("", Vec::new()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- from_entries: whitespace-only schema version ----------

#[test]
fn from_entries_whitespace_only_schema_version_fails() {
    let err = ModuleCompatibilityMatrix::from_entries("   ", Vec::new()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- from_entries: empty case_id ----------

#[test]
fn from_entries_empty_case_id_fails() {
    let mut entry = valid_entry_integ("valid");
    entry.case_id = "".to_string();
    let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- from_entries: whitespace-only case_id normalizes to empty ----------

#[test]
fn from_entries_whitespace_only_case_id_fails() {
    let mut entry = valid_entry_integ("valid");
    entry.case_id = "   ".to_string();
    let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- from_entries: duplicate case_id ----------

#[test]
fn from_entries_duplicate_case_id_fails() {
    let entry_a = valid_entry_integ("dup-case");
    let entry_b = valid_entry_integ("dup-case");
    let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry_a, entry_b]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::DuplicateCaseId);
}

// ---------- from_json_str: invalid JSON ----------

#[test]
fn from_json_str_invalid_json_fails() {
    let err = ModuleCompatibilityMatrix::from_json_str("not json at all").unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MatrixParseError);
}

#[test]
fn from_json_str_empty_string_fails() {
    let err = ModuleCompatibilityMatrix::from_json_str("").unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MatrixParseError);
}

// ---------- evaluate_observation: unknown case ----------

#[test]
fn evaluate_observation_unknown_case_fails() {
    let mut matrix =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![valid_entry_integ("known-case")])
            .unwrap();
    let obs = CompatibilityObservation::new(
        "unknown-case-xyz",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "behavior",
    );
    let err = matrix.evaluate_observation(&obs, &context()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::CaseNotFound);
}

// ---------- evaluate_observation: behavior mismatch ----------

#[test]
fn evaluate_observation_behavior_mismatch_fails() {
    let entry = valid_entry_integ("case-mismatch");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-mismatch",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "totally-wrong-behavior",
    );
    let err = matrix.evaluate_observation(&obs, &context()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::ObservationMismatch);
    assert!(err.message.contains("mismatch"));
}

// ---------- evaluate_observation: matching behavior succeeds ----------

#[test]
fn evaluate_observation_matching_behavior_succeeds() {
    let entry = valid_entry_integ("case-match");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-match",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "ok",
    );
    let outcome = matrix
        .evaluate_observation(&obs, &context())
        .expect("should match");
    assert!(outcome.matched);
    assert_eq!(outcome.case_id, "case-match");
    assert_eq!(outcome.expected_behavior, "ok");
    assert_eq!(outcome.observed_behavior, "ok");
    assert_eq!(outcome.event.outcome, "allow");
    assert_eq!(outcome.event.error_code, "none");
}

// ---------- evaluate_observation: Node runtime ----------

#[test]
fn evaluate_observation_node_runtime_matches() {
    let mut entry = valid_entry_integ("case-node-rt");
    entry.node_behavior = "node-specific-ok".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-node-rt",
        CompatibilityRuntime::Node,
        CompatibilityMode::Native,
        "node-specific-ok",
    );
    let outcome = matrix
        .evaluate_observation(&obs, &context())
        .expect("should match");
    assert!(outcome.matched);
    assert_eq!(outcome.runtime, CompatibilityRuntime::Node);
}

// ---------- evaluate_observation: Bun runtime ----------

#[test]
fn evaluate_observation_bun_runtime_matches() {
    let mut entry = valid_entry_integ("case-bun-rt");
    entry.bun_behavior = "bun-specific-ok".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-bun-rt",
        CompatibilityRuntime::Bun,
        CompatibilityMode::Native,
        "bun-specific-ok",
    );
    let outcome = matrix
        .evaluate_observation(&obs, &context())
        .expect("should match");
    assert!(outcome.matched);
    assert_eq!(outcome.runtime, CompatibilityRuntime::Bun);
}

// ---------- evaluate_observation: FrankenEngine NodeCompat mode ----------

#[test]
fn evaluate_observation_franken_node_compat_mode_matches() {
    let mut entry = valid_entry_integ("case-node-compat");
    entry.franken_node_compat_behavior = "compat-behavior".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-node-compat",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::NodeCompat,
        "compat-behavior",
    );
    let outcome = matrix
        .evaluate_observation(&obs, &context())
        .expect("should match");
    assert!(outcome.matched);
    assert_eq!(outcome.mode, CompatibilityMode::NodeCompat);
}

// ---------- evaluate_observation: FrankenEngine BunCompat mode ----------

#[test]
fn evaluate_observation_franken_bun_compat_mode_matches() {
    let mut entry = valid_entry_integ("case-bun-compat");
    entry.franken_bun_compat_behavior = "bun-compat-behavior".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-bun-compat",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::BunCompat,
        "bun-compat-behavior",
    );
    let outcome = matrix
        .evaluate_observation(&obs, &context())
        .expect("should match");
    assert!(outcome.matched);
    assert_eq!(outcome.mode, CompatibilityMode::BunCompat);
}

// ---------- evaluate_observation with divergence returns category ----------

#[test]
fn evaluate_observation_with_divergence_returns_category() {
    let mut entry = valid_entry_integ("case-cat");
    entry.franken_native_behavior = "strict-native".to_string();
    entry.franken_node_compat_behavior = "strict-native".to_string();
    entry.franken_bun_compat_behavior = "strict-native".to_string();
    entry.node_behavior = "lenient-node".to_string();
    entry.bun_behavior = "strict-native".to_string();
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "Strict security posture".to_string(),
        impact: "requires compat mode".to_string(),
        waiver_id: "w-cat".to_string(),
        migration_guidance: "switch to node_compat".to_string(),
    });
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::from(["w-cat".to_string()]), &context())
        .expect("should validate");
    let obs = CompatibilityObservation::new(
        "case-cat",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "strict-native",
    );
    let outcome = matrix
        .evaluate_observation(&obs, &context())
        .expect("should match");
    assert!(outcome.matched);
    assert!(outcome.divergence.is_some());
    assert!(outcome.divergence_category.is_some());
    assert!(outcome.actionable_guidance.is_some());
}

// ---------- evaluate_scenario: empty scenario_id fails ----------

#[test]
fn evaluate_scenario_empty_scenario_id_fails() {
    let entry = valid_entry_integ("case-scenario");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .evaluate_scenario("", &[], &context(), 1_000_000)
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn evaluate_scenario_whitespace_only_scenario_id_fails() {
    let entry = valid_entry_integ("case-scenario-ws");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .evaluate_scenario("   ", &[], &context(), 1_000_000)
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- evaluate_scenario: empty observations ----------

#[test]
fn evaluate_scenario_with_empty_observations() {
    let entry = valid_entry_integ("case-empty-obs");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let report = matrix
        .evaluate_scenario("scenario-empty", &[], &context(), 1_000_000)
        .expect("empty observations should succeed");
    assert_eq!(report.total_observations, 0);
    assert_eq!(report.matched_observations, 0);
    assert!(report.outcomes.is_empty());
    assert_eq!(
        report.schema_version,
        COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION
    );
}

// ---------- evaluate_scenario: multiple observations ----------

#[test]
fn evaluate_scenario_multiple_observations() {
    let entry_a = valid_entry_integ("case-a-multi");
    let mut entry_b = valid_entry_integ("case-b-multi");
    entry_b.feature = ModuleFeature::Cjs;
    entry_b.scenario = "cjs scenario".to_string();
    let mut matrix =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry_a, entry_b]).unwrap();
    let observations = [
        CompatibilityObservation::new(
            "case-a-multi",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "ok",
        ),
        CompatibilityObservation::new(
            "case-b-multi",
            CompatibilityRuntime::FrankenEngine,
            CompatibilityMode::Native,
            "ok",
        ),
    ];
    let report = matrix
        .evaluate_scenario("multi-scenario", &observations, &context(), 2_000_000)
        .expect("should succeed");
    assert_eq!(report.total_observations, 2);
    assert_eq!(report.matched_observations, 2);
    assert_eq!(report.outcomes.len(), 2);
    assert_eq!(report.scenario_id, "multi-scenario");
    assert_eq!(report.generated_at_unix_ms, 2_000_000);
    assert_eq!(report.trace_id, "trace-modcompat-integration");
}

// ---------- evaluate_scenario: observation mismatch propagates error ----------

#[test]
fn evaluate_scenario_propagates_observation_mismatch() {
    let entry = valid_entry_integ("case-scenario-mismatch");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let observations = [CompatibilityObservation::new(
        "case-scenario-mismatch",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "wrong-behavior",
    )];
    let err = matrix
        .evaluate_scenario("bad-scenario", &observations, &context(), 1_000)
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::ObservationMismatch);
}

// ---------- validate_with_waivers: all behaviors match, no divergence needed ----------

#[test]
fn validate_with_waivers_all_match_succeeds() {
    let entry = valid_entry_integ("case-all-match");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect("all matching behaviors should validate without waivers");
    assert!(!matrix.events().is_empty());
}

// ---------- validate: hidden shim for NodeCompat ----------

#[test]
fn validate_hidden_shim_node_compat_fails() {
    let mut entry = valid_entry_integ("case-hidden-nc");
    entry.franken_node_compat_behavior = "different-nc".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::HiddenShim);
}

// ---------- validate: hidden shim for BunCompat ----------

#[test]
fn validate_hidden_shim_bun_compat_fails() {
    let mut entry = valid_entry_integ("case-hidden-bc");
    entry.franken_bun_compat_behavior = "different-bc".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::HiddenShim);
}

// ---------- validate: shim present resolves hidden shim ----------

#[test]
fn validate_explicit_shim_resolves_hidden_shim_node_compat() {
    let mut entry = valid_entry_integ("case-shim-nc");
    entry.franken_node_compat_behavior = "different-nc".to_string();
    entry.explicit_shims = vec![valid_shim_integ(CompatibilityMode::NodeCompat)];
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect("explicit shim should resolve hidden shim");
}

#[test]
fn validate_explicit_shim_resolves_hidden_shim_bun_compat() {
    let mut entry = valid_entry_integ("case-shim-bc");
    entry.franken_bun_compat_behavior = "different-bc".to_string();
    entry.explicit_shims = vec![valid_shim_integ(CompatibilityMode::BunCompat)];
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect("explicit shim should resolve hidden shim");
}

// ---------- validate: divergence present but native matches references ----------

#[test]
fn validate_divergence_present_but_no_mismatch_fails() {
    let mut entry = valid_entry_integ("case-false-div");
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "spurious".to_string(),
        impact: "none".to_string(),
        waiver_id: "w-false".to_string(),
        migration_guidance: "remove divergence".to_string(),
    });
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::from(["w-false".to_string()]), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- validate: native diverges but no divergence policy ----------

#[test]
fn validate_divergent_without_policy_fails() {
    let mut entry = valid_entry_integ("case-no-policy");
    entry.franken_native_behavior = "native-diff".to_string();
    entry.franken_node_compat_behavior = "native-diff".to_string();
    entry.franken_bun_compat_behavior = "native-diff".to_string();
    entry.node_behavior = "node-diff".to_string();
    entry.bun_behavior = "native-diff".to_string();
    entry.divergence = None;
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
}

// ---------- validate: runtime set mismatch ----------

#[test]
fn validate_runtime_set_mismatch_fails() {
    let mut entry = valid_entry_integ("case-rt-mismatch");
    entry.franken_native_behavior = "native".to_string();
    entry.franken_node_compat_behavior = "native".to_string();
    entry.franken_bun_compat_behavior = "native".to_string();
    entry.node_behavior = "node-diff".to_string();
    entry.bun_behavior = "bun-diff".to_string();
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "only node declared".to_string(),
        impact: "none".to_string(),
        waiver_id: "w-rt".to_string(),
        migration_guidance: "fix".to_string(),
    });
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::from(["w-rt".to_string()]), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- validate: empty waiver_id ----------

#[test]
fn validate_empty_waiver_id_fails() {
    let mut entry = valid_entry_integ("case-empty-wid");
    entry.franken_native_behavior = "native".to_string();
    entry.franken_node_compat_behavior = "native".to_string();
    entry.franken_bun_compat_behavior = "native".to_string();
    entry.node_behavior = "node-diff".to_string();
    entry.bun_behavior = "native".to_string();
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "r".to_string(),
        impact: "i".to_string(),
        waiver_id: "".to_string(),
        migration_guidance: "g".to_string(),
    });
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
}

// ---------- validate: empty migration_guidance ----------

#[test]
fn validate_empty_migration_guidance_fails() {
    let mut entry = valid_entry_integ("case-no-guide");
    entry.franken_native_behavior = "native".to_string();
    entry.franken_node_compat_behavior = "native".to_string();
    entry.franken_bun_compat_behavior = "native".to_string();
    entry.node_behavior = "node-diff".to_string();
    entry.bun_behavior = "native".to_string();
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "r".to_string(),
        impact: "i".to_string(),
        waiver_id: "w-guide".to_string(),
        migration_guidance: "".to_string(),
    });
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::from(["w-guide".to_string()]), &context())
        .unwrap_err();
    assert_eq!(
        err.code,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance
    );
}

// ---------- validate: valid entry with divergence passes ----------

#[test]
fn validate_valid_divergence_passes() {
    let mut entry = valid_entry_integ("case-valid-div");
    entry.franken_native_behavior = "native-v".to_string();
    entry.franken_node_compat_behavior = "native-v".to_string();
    entry.franken_bun_compat_behavior = "native-v".to_string();
    entry.node_behavior = "node-diff-v".to_string();
    entry.bun_behavior = "native-v".to_string();
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "valid reason".to_string(),
        impact: "low".to_string(),
        waiver_id: "w-valid".to_string(),
        migration_guidance: "valid guidance".to_string(),
    });
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::from(["w-valid".to_string()]), &context())
        .expect("valid divergence entry should pass");
}

// ---------- validate: shim validation edge cases ----------

#[test]
fn validate_shim_empty_scenario_fails() {
    let mut entry = valid_entry_integ("case-empty-scen");
    entry.scenario = "".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_empty_lockstep_refs_fails() {
    let mut entry = valid_entry_integ("case-no-lockstep");
    entry.lockstep_case_refs.clear();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_empty_test262_refs_fails() {
    let mut entry = valid_entry_integ("case-no-test262");
    entry.test262_refs.clear();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_not_removable_fails() {
    let mut entry = valid_entry_integ("case-not-removable");
    entry.franken_node_compat_behavior = "different".to_string();
    let mut shim = valid_shim_integ(CompatibilityMode::NodeCompat);
    shim.removable = false;
    entry.explicit_shims = vec![shim];
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_empty_shim_id_fails() {
    let mut entry = valid_entry_integ("case-empty-shimid");
    entry.franken_node_compat_behavior = "different".to_string();
    let mut shim = valid_shim_integ(CompatibilityMode::NodeCompat);
    shim.shim_id = "".to_string();
    entry.explicit_shims = vec![shim];
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_empty_description_fails() {
    let mut entry = valid_entry_integ("case-empty-desc");
    entry.franken_node_compat_behavior = "different".to_string();
    let mut shim = valid_shim_integ(CompatibilityMode::NodeCompat);
    shim.description = "".to_string();
    entry.explicit_shims = vec![shim];
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_empty_test_case_ref_fails() {
    let mut entry = valid_entry_integ("case-empty-tcr");
    entry.franken_node_compat_behavior = "different".to_string();
    let mut shim = valid_shim_integ(CompatibilityMode::NodeCompat);
    shim.test_case_ref = "".to_string();
    entry.explicit_shims = vec![shim];
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------- events: incrementing sequence ----------

#[test]
fn events_have_incrementing_sequence_numbers() {
    let mut matrix = ModuleCompatibilityMatrix::from_entries(
        "1.0.0",
        vec![
            valid_entry_integ("case-seq-1"),
            valid_entry_integ("case-seq-2"),
            valid_entry_integ("case-seq-3"),
        ],
    )
    .unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect("valid entries should pass");
    let events = matrix.events();
    assert!(events.len() >= 3);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.seq, i as u64, "event seq mismatch at index {i}");
    }
}

// ---------- events: initially empty ----------

#[test]
fn events_empty_initially() {
    let matrix =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![valid_entry_integ("case-init")])
            .unwrap();
    assert!(matrix.events().is_empty());
}

// ---------- events: component is always module_compatibility_matrix ----------

#[test]
fn events_component_is_module_compatibility_matrix() {
    let entry = valid_entry_integ("case-comp");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect("valid entry");
    for event in matrix.events() {
        assert_eq!(event.component, "module_compatibility_matrix");
    }
}

// ---------- canonical_hash changes with different content ----------

#[test]
fn canonical_hash_differs_for_different_schema_versions() {
    let entry = valid_entry_integ("case-sv");
    let matrix_a = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry.clone()]).unwrap();
    let matrix_b = ModuleCompatibilityMatrix::from_entries("2.0.0", vec![entry]).unwrap();
    assert_ne!(matrix_a.canonical_hash(), matrix_b.canonical_hash());
}

#[test]
fn canonical_hash_differs_for_different_entries() {
    let matrix_a =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![valid_entry_integ("a")]).unwrap();
    let matrix_b =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![valid_entry_integ("b")]).unwrap();
    assert_ne!(matrix_a.canonical_hash(), matrix_b.canonical_hash());
}

// ---------- to_json_pretty roundtrip ----------

#[test]
fn to_json_pretty_roundtrip_preserves_hash() {
    let matrix =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![valid_entry_integ("case-rt")])
            .unwrap();
    let json = matrix.to_json_pretty().expect("serialize");
    let reparsed = ModuleCompatibilityMatrix::from_json_str(&json).expect("re-parse");
    assert_eq!(matrix.canonical_hash(), reparsed.canonical_hash());
}

// ---------- required_waiver_ids: empty when no divergence ----------

#[test]
fn required_waiver_ids_empty_without_divergence() {
    let matrix =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![valid_entry_integ("case-no-waiver")])
            .unwrap();
    assert!(matrix.required_waiver_ids().is_empty());
}

// ---------- required_waiver_ids: deduplicates ----------

#[test]
fn required_waiver_ids_deduplicates_shared_waiver() {
    let mut entry_a = valid_entry_integ("case-wa");
    entry_a.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "r".to_string(),
        impact: "i".to_string(),
        waiver_id: "shared-w".to_string(),
        migration_guidance: "g".to_string(),
    });
    let mut entry_b = valid_entry_integ("case-wb");
    entry_b.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Bun],
        reason: "r".to_string(),
        impact: "i".to_string(),
        waiver_id: "shared-w".to_string(),
        migration_guidance: "g".to_string(),
    });
    let matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry_a, entry_b]).unwrap();
    let waivers = matrix.required_waiver_ids();
    assert_eq!(waivers.len(), 1);
    assert!(waivers.contains("shared-w"));
}

// ---------- entries: multiple entries ----------

#[test]
fn entries_returns_all_inserted() {
    let matrix = ModuleCompatibilityMatrix::from_entries(
        "1.0.0",
        vec![
            valid_entry_integ("x"),
            valid_entry_integ("y"),
            valid_entry_integ("z"),
        ],
    )
    .unwrap();
    assert_eq!(matrix.entries().len(), 3);
    assert!(matrix.entry("x").is_some());
    assert!(matrix.entry("y").is_some());
    assert!(matrix.entry("z").is_some());
}

// ---------- ModuleFeature serde JSON values ----------

#[test]
fn module_feature_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&ModuleFeature::Esm).unwrap(),
        "\"esm\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleFeature::Cjs).unwrap(),
        "\"cjs\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleFeature::DualMode).unwrap(),
        "\"dual_mode\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleFeature::ConditionalExports).unwrap(),
        "\"conditional_exports\""
    );
    assert_eq!(
        serde_json::to_string(&ModuleFeature::PackageJsonFields).unwrap(),
        "\"package_json_fields\""
    );
}

// ---------- CompatibilityRuntime serde JSON values ----------

#[test]
fn compatibility_runtime_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&CompatibilityRuntime::FrankenEngine).unwrap(),
        "\"franken_engine\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityRuntime::Node).unwrap(),
        "\"node\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityRuntime::Bun).unwrap(),
        "\"bun\""
    );
}

// ---------- CompatibilityMode serde JSON values ----------

#[test]
fn compatibility_mode_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&CompatibilityMode::Native).unwrap(),
        "\"native\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMode::NodeCompat).unwrap(),
        "\"node_compat\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMode::BunCompat).unwrap(),
        "\"bun_compat\""
    );
}

// ---------- ReferenceRuntime serde JSON values ----------

#[test]
fn reference_runtime_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&ReferenceRuntime::Node).unwrap(),
        "\"node\""
    );
    assert_eq!(
        serde_json::to_string(&ReferenceRuntime::Bun).unwrap(),
        "\"bun\""
    );
}

// ---------- DivergenceCategory serde JSON values ----------

#[test]
fn divergence_category_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&DivergenceCategory::EngineBug).unwrap(),
        "\"engine_bug\""
    );
    assert_eq!(
        serde_json::to_string(&DivergenceCategory::IntentionalImprovement).unwrap(),
        "\"intentional_improvement\""
    );
    assert_eq!(
        serde_json::to_string(&DivergenceCategory::CompatibilityDebt).unwrap(),
        "\"compatibility_debt\""
    );
    assert_eq!(
        serde_json::to_string(&DivergenceCategory::EcosystemAmbiguity).unwrap(),
        "\"ecosystem_ambiguity\""
    );
    assert_eq!(
        serde_json::to_string(&DivergenceCategory::ReferenceRuntimeBug).unwrap(),
        "\"reference_runtime_bug\""
    );
}

// ---------- CompatibilityMatrixErrorCode serde JSON values ----------

#[test]
fn error_code_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::MatrixParseError).unwrap(),
        "\"matrix_parse_error\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::DuplicateCaseId).unwrap(),
        "\"duplicate_case_id\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::CaseNotFound).unwrap(),
        "\"case_not_found\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::HiddenShim).unwrap(),
        "\"hidden_shim\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::MissingWaiver).unwrap(),
        "\"missing_waiver\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::MissingMigrationGuidance).unwrap(),
        "\"missing_migration_guidance\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::InvalidMatrix).unwrap(),
        "\"invalid_matrix\""
    );
    assert_eq!(
        serde_json::to_string(&CompatibilityMatrixErrorCode::ObservationMismatch).unwrap(),
        "\"observation_mismatch\""
    );
}

// ---------- CompatibilityObservation: all runtime/mode combos ----------

#[test]
fn compatibility_observation_new_all_runtime_mode_combos() {
    for runtime in [
        CompatibilityRuntime::FrankenEngine,
        CompatibilityRuntime::Node,
        CompatibilityRuntime::Bun,
    ] {
        for mode in [
            CompatibilityMode::Native,
            CompatibilityMode::NodeCompat,
            CompatibilityMode::BunCompat,
        ] {
            let obs = CompatibilityObservation::new("combo-case", runtime, mode, "behavior");
            assert_eq!(obs.case_id, "combo-case");
            assert_eq!(obs.runtime, runtime);
            assert_eq!(obs.mode, mode);
            assert_eq!(obs.observed_behavior, "behavior");
        }
    }
}

// ---------- default matrix entries all have nonempty scenario ----------

#[test]
fn default_matrix_entries_all_have_nonempty_scenario() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    for entry in matrix.entries() {
        assert!(
            !entry.scenario.trim().is_empty(),
            "entry {} must have non-empty scenario",
            entry.case_id
        );
    }
}

// ---------- default matrix entries all have lockstep and test262 refs ----------

#[test]
fn default_matrix_entries_all_have_lockstep_refs() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    for entry in matrix.entries() {
        assert!(
            !entry.lockstep_case_refs.is_empty(),
            "entry {} must have lockstep_case_refs",
            entry.case_id
        );
    }
}

#[test]
fn default_matrix_entries_all_have_test262_refs() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    for entry in matrix.entries() {
        assert!(
            !entry.test262_refs.is_empty(),
            "entry {} must have test262_refs",
            entry.case_id
        );
    }
}

// ---------- validate_against_tracker with no waivers registered fails ----------

#[test]
fn validate_against_tracker_no_waivers_fails_when_needed() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().expect("load matrix");
    let tracker = FeatureParityTracker::new();
    let err = matrix
        .validate_against_tracker(&tracker, &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
}

// ---------- CompatibilityScenarioReport with divergence counts ----------

#[test]
fn scenario_report_tracks_divergence_category_counts() {
    let mut entry = valid_entry_integ("case-cat-count");
    entry.franken_native_behavior = "strict".to_string();
    entry.franken_node_compat_behavior = "strict".to_string();
    entry.franken_bun_compat_behavior = "strict".to_string();
    entry.node_behavior = "lenient".to_string();
    entry.bun_behavior = "strict".to_string();
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "strict security".to_string(),
        impact: "requires compat mode".to_string(),
        waiver_id: "w-count".to_string(),
        migration_guidance: "use node_compat".to_string(),
    });
    let clean = valid_entry_integ("case-clean-count");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry, clean]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::from(["w-count".to_string()]), &context())
        .expect("validation");

    let report = matrix
        .evaluate_scenario(
            "counting-scenario",
            &[
                CompatibilityObservation::new(
                    "case-cat-count",
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    "strict",
                ),
                CompatibilityObservation::new(
                    "case-clean-count",
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    "ok",
                ),
            ],
            &context(),
            1_800_000_000_000,
        )
        .expect("scenario evaluation");
    assert_eq!(report.total_observations, 2);
    assert_eq!(report.matched_observations, 2);
    assert!(
        report.divergence_category_counts.values().sum::<u64>() >= 1,
        "should have at least one divergence category counted"
    );
}

// ---------- Debug impls nonempty ----------

#[test]
fn module_feature_debug_is_nonempty() {
    for feature in [
        ModuleFeature::Esm,
        ModuleFeature::Cjs,
        ModuleFeature::DualMode,
        ModuleFeature::ConditionalExports,
        ModuleFeature::PackageJsonFields,
    ] {
        assert!(!format!("{feature:?}").is_empty());
    }
}

#[test]
fn compatibility_runtime_debug_is_nonempty() {
    for runtime in [
        CompatibilityRuntime::FrankenEngine,
        CompatibilityRuntime::Node,
        CompatibilityRuntime::Bun,
    ] {
        assert!(!format!("{runtime:?}").is_empty());
    }
}

#[test]
fn compatibility_mode_debug_is_nonempty() {
    for mode in [
        CompatibilityMode::Native,
        CompatibilityMode::NodeCompat,
        CompatibilityMode::BunCompat,
    ] {
        assert!(!format!("{mode:?}").is_empty());
    }
}

#[test]
fn reference_runtime_debug_is_nonempty() {
    for rt in [ReferenceRuntime::Node, ReferenceRuntime::Bun] {
        assert!(!format!("{rt:?}").is_empty());
    }
}

#[test]
fn divergence_category_debug_is_nonempty() {
    for cat in [
        DivergenceCategory::EngineBug,
        DivergenceCategory::IntentionalImprovement,
        DivergenceCategory::CompatibilityDebt,
        DivergenceCategory::EcosystemAmbiguity,
        DivergenceCategory::ReferenceRuntimeBug,
    ] {
        assert!(!format!("{cat:?}").is_empty());
    }
}

#[test]
fn error_code_debug_is_nonempty() {
    for code in [
        CompatibilityMatrixErrorCode::MatrixParseError,
        CompatibilityMatrixErrorCode::DuplicateCaseId,
        CompatibilityMatrixErrorCode::CaseNotFound,
        CompatibilityMatrixErrorCode::HiddenShim,
        CompatibilityMatrixErrorCode::MissingWaiver,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance,
        CompatibilityMatrixErrorCode::InvalidMatrix,
        CompatibilityMatrixErrorCode::ObservationMismatch,
    ] {
        assert!(!format!("{code:?}").is_empty());
    }
}

// ---------- Clone impls ----------

#[test]
fn module_feature_clone() {
    let original = ModuleFeature::DualMode;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn compatibility_runtime_clone() {
    let original = CompatibilityRuntime::Bun;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn compatibility_mode_clone() {
    let original = CompatibilityMode::BunCompat;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn reference_runtime_clone() {
    let original = ReferenceRuntime::Bun;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn divergence_category_clone() {
    let original = DivergenceCategory::EcosystemAmbiguity;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn explicit_shim_clone() {
    let original = valid_shim_integ(CompatibilityMode::Native);
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn divergence_policy_clone() {
    let original = DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node, ReferenceRuntime::Bun],
        reason: "clone test".to_string(),
        impact: "none".to_string(),
        waiver_id: "w-clone".to_string(),
        migration_guidance: "clone guidance".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn compatibility_matrix_entry_clone() {
    let original = valid_entry_integ("case-clone");
    let cloned = original.clone();
    assert_eq!(original, cloned);
}
