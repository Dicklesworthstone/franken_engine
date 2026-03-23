#![allow(clippy::too_many_arguments)]

//! Enrichment integration tests for `module_compatibility_matrix`.

use std::{collections::BTreeSet, fs, path::PathBuf};

use frankenengine_engine::module_compatibility_matrix::*;

fn context() -> CompatibilityContext {
    CompatibilityContext::new("trace-enrich", "decision-enrich", "policy-enrich")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn valid_entry(case_id: &str) -> CompatibilityMatrixEntry {
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

fn valid_shim(mode: CompatibilityMode) -> ExplicitShim {
    ExplicitShim {
        shim_id: "shim-1".to_string(),
        mode,
        description: "shim description".to_string(),
        removable: true,
        test_case_ref: "test/ref.js".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Enum serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn module_feature_serde_roundtrip() {
    for v in [
        ModuleFeature::Esm,
        ModuleFeature::Cjs,
        ModuleFeature::DualMode,
        ModuleFeature::ConditionalExports,
        ModuleFeature::PackageJsonFields,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ModuleFeature = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn compatibility_runtime_serde_roundtrip() {
    for v in [
        CompatibilityRuntime::FrankenEngine,
        CompatibilityRuntime::Node,
        CompatibilityRuntime::Bun,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: CompatibilityRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn compatibility_mode_serde_roundtrip() {
    for v in [
        CompatibilityMode::Native,
        CompatibilityMode::NodeCompat,
        CompatibilityMode::BunCompat,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: CompatibilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn reference_runtime_serde_roundtrip() {
    for v in [ReferenceRuntime::Node, ReferenceRuntime::Bun] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ReferenceRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn error_code_serde_roundtrip() {
    for v in [
        CompatibilityMatrixErrorCode::MatrixParseError,
        CompatibilityMatrixErrorCode::DuplicateCaseId,
        CompatibilityMatrixErrorCode::CaseNotFound,
        CompatibilityMatrixErrorCode::HiddenShim,
        CompatibilityMatrixErrorCode::MissingWaiver,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance,
        CompatibilityMatrixErrorCode::InvalidMatrix,
        CompatibilityMatrixErrorCode::ObservationMismatch,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: CompatibilityMatrixErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn divergence_category_serde_roundtrip() {
    for v in [
        DivergenceCategory::EngineBug,
        DivergenceCategory::IntentionalImprovement,
        DivergenceCategory::CompatibilityDebt,
        DivergenceCategory::EcosystemAmbiguity,
        DivergenceCategory::ReferenceRuntimeBug,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: DivergenceCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// Enum as_str
// ---------------------------------------------------------------------------

#[test]
fn module_feature_as_str_values() {
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

#[test]
fn compatibility_runtime_as_str_values() {
    assert_eq!(
        CompatibilityRuntime::FrankenEngine.as_str(),
        "franken_engine"
    );
    assert_eq!(CompatibilityRuntime::Node.as_str(), "node");
    assert_eq!(CompatibilityRuntime::Bun.as_str(), "bun");
}

#[test]
fn compatibility_mode_as_str_values() {
    assert_eq!(CompatibilityMode::Native.as_str(), "native");
    assert_eq!(CompatibilityMode::NodeCompat.as_str(), "node_compat");
    assert_eq!(CompatibilityMode::BunCompat.as_str(), "bun_compat");
}

// ---------------------------------------------------------------------------
// Error code stable codes
// ---------------------------------------------------------------------------

#[test]
fn error_code_stable_codes_unique() {
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
    let strs: BTreeSet<&str> = codes.iter().map(|c| c.stable_code()).collect();
    assert_eq!(strs.len(), codes.len());
}

#[test]
fn error_code_stable_codes_prefixed() {
    let codes = [
        CompatibilityMatrixErrorCode::MatrixParseError,
        CompatibilityMatrixErrorCode::DuplicateCaseId,
        CompatibilityMatrixErrorCode::CaseNotFound,
    ];
    for c in codes {
        assert!(c.stable_code().starts_with("FE-MODCOMP-"));
    }
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn error_display_without_event() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::InvalidMatrix,
        message: "bad matrix".to_string(),
        event: None,
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-MODCOMP-0007"));
    assert!(msg.contains("bad matrix"));
}

#[test]
fn error_display_with_event_includes_trace_ids() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::CaseNotFound,
        message: "not found".to_string(),
        event: Some(CompatibilityEvent {
            seq: 0,
            trace_id: "t-abc".to_string(),
            decision_id: "d-xyz".to_string(),
            policy_id: "p-123".to_string(),
            component: "test".to_string(),
            event: "lookup".to_string(),
            outcome: "error".to_string(),
            error_code: "FE-MODCOMP-0003".to_string(),
            case_id: "c1".to_string(),
            runtime: "franken_engine".to_string(),
            mode: "native".to_string(),
            detail: "missing".to_string(),
        }),
    };
    let msg = err.to_string();
    assert!(msg.contains("t-abc"));
    assert!(msg.contains("d-xyz"));
    assert!(msg.contains("p-123"));
}

#[test]
fn interop_gate_script_emits_trace_ids_artifact_contract() {
    let path = repo_root().join("scripts/run_rgc_module_interop_verification_matrix.sh");
    let script = read_to_string(&path);

    for needle in [
        "trace_ids_path=\"${run_dir}/trace_ids.json\"",
        "write_trace_ids()",
        "\"trace_ids\": \"${trace_ids_path}\"",
        "cat ${trace_ids_path}",
        "rgc module interop verification matrix trace ids: ${trace_ids_path}",
        "write_trace_ids\nwrite_manifest \"$main_exit\"",
    ] {
        assert!(script.contains(needle), "gate script missing {needle}");
    }
}

#[test]
fn interop_replay_wrapper_requires_and_surfaces_trace_ids_artifact() {
    let path = repo_root().join("scripts/e2e/rgc_module_interop_verification_matrix_replay.sh");
    let script = read_to_string(&path);

    for needle in ["trace_ids.json", "latest trace ids"] {
        assert!(script.contains(needle), "replay wrapper missing {needle}");
    }
}

// ---------------------------------------------------------------------------
// from_entries validation
// ---------------------------------------------------------------------------

#[test]
fn from_entries_empty_schema_fails() {
    let err = ModuleCompatibilityMatrix::from_entries("", Vec::new()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn from_entries_empty_case_id_fails() {
    let mut entry = valid_entry("case-1");
    entry.case_id.clear();
    let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn from_entries_duplicate_case_id_fails() {
    let entry = valid_entry("dup");
    let err =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry.clone(), entry]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::DuplicateCaseId);
}

#[test]
fn from_json_str_invalid_json_fails() {
    let err = ModuleCompatibilityMatrix::from_json_str("not json").unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MatrixParseError);
}

// ---------------------------------------------------------------------------
// Default matrix
// ---------------------------------------------------------------------------

#[test]
fn default_matrix_deterministic_hash() {
    let a = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let b = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert_eq!(a.canonical_hash(), b.canonical_hash());
}

#[test]
fn default_matrix_has_entries() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert!(!matrix.entries().is_empty());
}

#[test]
fn default_matrix_events_empty_initially() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert!(matrix.events().is_empty());
}

#[test]
fn default_matrix_has_required_waivers() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert!(!matrix.required_waiver_ids().is_empty());
}

// ---------------------------------------------------------------------------
// entry lookup
// ---------------------------------------------------------------------------

#[test]
fn entry_lookup_found() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let first_id = &matrix.entries()[0].case_id;
    assert!(matrix.entry(first_id).is_some());
}

#[test]
fn entry_lookup_not_found() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert!(matrix.entry("nonexistent-xyz").is_none());
}

// ---------------------------------------------------------------------------
// validate_with_waivers
// ---------------------------------------------------------------------------

#[test]
fn validate_valid_entry_passes() {
    let entry = valid_entry("case-ok");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .expect("valid entry should pass");
    assert!(!matrix.events().is_empty());
}

#[test]
fn validate_empty_scenario_fails() {
    let mut entry = valid_entry("case-1");
    entry.scenario.clear();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_empty_lockstep_refs_fails() {
    let mut entry = valid_entry("case-1");
    entry.lockstep_case_refs.clear();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_empty_test262_refs_fails() {
    let mut entry = valid_entry("case-1");
    entry.test262_refs.clear();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_hidden_shim_node_compat_fails() {
    let mut entry = valid_entry("case-shim");
    entry.franken_node_compat_behavior = "different".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::HiddenShim);
}

#[test]
fn validate_hidden_shim_bun_compat_fails() {
    let mut entry = valid_entry("case-shim");
    entry.franken_bun_compat_behavior = "different".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::HiddenShim);
}

#[test]
fn validate_divergence_without_mismatch_fails() {
    let mut entry = valid_entry("case-div");
    entry.divergence = Some(DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node],
        reason: "reason".into(),
        impact: "impact".into(),
        waiver_id: "w-1".into(),
        migration_guidance: "guidance".into(),
    });
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .validate_with_waivers(&BTreeSet::from(["w-1".to_string()]), &context())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_mismatched_behavior_without_waiver_fails() {
    let mut entry = valid_entry("case-1");
    entry.franken_native_behavior = "native".into();
    entry.node_behavior = "different".into();
    entry.divergence = None;
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    // Validation catches either HiddenShim or MissingWaiver depending on
    // which check fires first — both are valid failure modes for mismatched
    // behaviors without explicit divergence/waiver.
    let err = matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap_err();
    assert!(
        err.code == CompatibilityMatrixErrorCode::MissingWaiver
            || err.code == CompatibilityMatrixErrorCode::HiddenShim,
        "expected MissingWaiver or HiddenShim, got {:?}",
        err.code
    );
}

// ---------------------------------------------------------------------------
// evaluate_observation
// ---------------------------------------------------------------------------

#[test]
fn evaluate_observation_unknown_case_fails() {
    let mut matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let obs = CompatibilityObservation::new(
        "nonexistent-case",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "some behavior",
    );
    let err = matrix.evaluate_observation(&obs, &context()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::CaseNotFound);
}

#[test]
fn evaluate_observation_matching_behavior_succeeds() {
    let entry = valid_entry("case-obs");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-obs",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "ok",
    );
    let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
    assert!(outcome.matched);
    assert_eq!(outcome.expected_behavior, "ok");
}

#[test]
fn evaluate_observation_mismatch_fails() {
    let entry = valid_entry("case-obs");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-obs",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "unexpected",
    );
    let err = matrix.evaluate_observation(&obs, &context()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::ObservationMismatch);
}

#[test]
fn evaluate_observation_node_runtime() {
    let mut entry = valid_entry("case-node");
    entry.node_behavior = "node-ok".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-node",
        CompatibilityRuntime::Node,
        CompatibilityMode::Native,
        "node-ok",
    );
    let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
    assert!(outcome.matched);
}

#[test]
fn evaluate_observation_bun_runtime() {
    let mut entry = valid_entry("case-bun");
    entry.bun_behavior = "bun-ok".to_string();
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let obs = CompatibilityObservation::new(
        "case-bun",
        CompatibilityRuntime::Bun,
        CompatibilityMode::Native,
        "bun-ok",
    );
    let outcome = matrix.evaluate_observation(&obs, &context()).unwrap();
    assert!(outcome.matched);
}

// ---------------------------------------------------------------------------
// evaluate_scenario
// ---------------------------------------------------------------------------

#[test]
fn evaluate_scenario_produces_report() {
    let entry = valid_entry("case-scen");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let report = matrix
        .evaluate_scenario(
            "scenario-1",
            &[CompatibilityObservation::new(
                "case-scen",
                CompatibilityRuntime::FrankenEngine,
                CompatibilityMode::Native,
                "ok",
            )],
            &context(),
            1_700_000_000_000,
        )
        .unwrap();
    assert_eq!(report.scenario_id, "scenario-1");
    assert_eq!(report.total_observations, 1);
    assert_eq!(report.matched_observations, 1);
    assert_eq!(
        report.schema_version,
        COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION
    );
}

#[test]
fn evaluate_scenario_empty_id_fails() {
    let entry = valid_entry("case-1");
    let mut matrix = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![entry]).unwrap();
    let err = matrix
        .evaluate_scenario("", &[], &context(), 0)
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ---------------------------------------------------------------------------
// Canonical hash determinism
// ---------------------------------------------------------------------------

#[test]
fn canonical_hash_deterministic() {
    let a = ModuleCompatibilityMatrix::from_entries("v1", vec![valid_entry("a")]).unwrap();
    let h1 = a.canonical_hash();
    let h2 = a.canonical_hash();
    assert_eq!(h1, h2);
}

#[test]
fn canonical_hash_differs_for_different_entries() {
    let a = ModuleCompatibilityMatrix::from_entries("v1", vec![valid_entry("a")]).unwrap();
    let b = ModuleCompatibilityMatrix::from_entries("v1", vec![valid_entry("b")]).unwrap();
    assert_ne!(a.canonical_hash(), b.canonical_hash());
}

// ---------------------------------------------------------------------------
// to_json_pretty round-trip
// ---------------------------------------------------------------------------

#[test]
fn to_json_pretty_roundtrips() {
    let matrix = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let json = matrix.to_json_pretty().unwrap();
    let reparsed = ModuleCompatibilityMatrix::from_json_str(&json).unwrap();
    assert_eq!(matrix.canonical_hash(), reparsed.canonical_hash());
}

// ---------------------------------------------------------------------------
// Event sequencing
// ---------------------------------------------------------------------------

#[test]
fn events_have_incrementing_seq() {
    let mut matrix =
        ModuleCompatibilityMatrix::from_entries("1.0.0", vec![valid_entry("a"), valid_entry("b")])
            .unwrap();
    matrix
        .validate_with_waivers(&BTreeSet::new(), &context())
        .unwrap();
    let events = matrix.events();
    assert!(events.len() >= 2);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

// ---------------------------------------------------------------------------
// Serde round-trips for compound types
// ---------------------------------------------------------------------------

#[test]
fn explicit_shim_serde_roundtrip() {
    let shim = valid_shim(CompatibilityMode::NodeCompat);
    let json = serde_json::to_string(&shim).unwrap();
    let back: ExplicitShim = serde_json::from_str(&json).unwrap();
    assert_eq!(shim, back);
}

#[test]
fn divergence_policy_serde_roundtrip() {
    let policy = DivergencePolicy {
        diverges_from: vec![ReferenceRuntime::Node, ReferenceRuntime::Bun],
        reason: "intentional".into(),
        impact: "low".into(),
        waiver_id: "w-1".into(),
        migration_guidance: "use compat".into(),
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: DivergencePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn compatibility_context_serde_roundtrip() {
    let ctx = context();
    let json = serde_json::to_string(&ctx).unwrap();
    let back: CompatibilityContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn compatibility_observation_serde_roundtrip() {
    let obs = CompatibilityObservation::new(
        "case-1",
        CompatibilityRuntime::Node,
        CompatibilityMode::Native,
        "ok",
    );
    let json = serde_json::to_string(&obs).unwrap();
    let back: CompatibilityObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn compatibility_error_serde_roundtrip() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::CaseNotFound,
        message: "not found".into(),
        event: None,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: CompatibilityMatrixError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn compatibility_entry_serde_roundtrip() {
    let entry = valid_entry("serde-test");
    let json = serde_json::to_string(&entry).unwrap();
    let back: CompatibilityMatrixEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

#[test]
fn module_feature_ordering() {
    assert!(ModuleFeature::Esm < ModuleFeature::PackageJsonFields);
}

#[test]
fn compatibility_runtime_ordering() {
    assert!(CompatibilityRuntime::FrankenEngine < CompatibilityRuntime::Bun);
}

#[test]
fn compatibility_mode_ordering() {
    assert!(CompatibilityMode::Native < CompatibilityMode::BunCompat);
}

#[test]
fn reference_runtime_ordering() {
    assert!(ReferenceRuntime::Node < ReferenceRuntime::Bun);
}
