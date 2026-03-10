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

use std::collections::BTreeSet;

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
