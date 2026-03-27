#![forbid(unsafe_code)]

//! Integration tests for `module_compatibility_matrix` module.
//! Exercises the public API from outside the crate boundary.

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
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::esm_cjs_interop_parity::{
    InteropActualOutcome, InteropCompatibilityDisposition, run_interop_parity_corpus,
};
use frankenengine_engine::module_compatibility_matrix::{
    COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION, CompatibilityContext, CompatibilityMatrixEntry,
    CompatibilityMatrixError, CompatibilityMatrixErrorCode, CompatibilityMode,
    CompatibilityObservation, CompatibilityRuntime, DEFAULT_MATRIX_JSON, DivergencePolicy,
    ExplicitShim, ModuleCompatibilityMatrix, ModuleFeature, ReferenceRuntime,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx() -> CompatibilityContext {
    CompatibilityContext::new("trace-integ", "decision-integ", "policy-integ")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_interop_gate_script() -> String {
    let path = repo_root().join("scripts/run_rgc_module_interop_verification_matrix.sh");
    read_to_string(&path)
}

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
fn interop_gate_script_uses_repo_local_target_dir_and_fails_closed_on_rch_drift() {
    let script = read_interop_gate_script();

    assert!(
        script.contains("${root_dir}/target_rch_rgc_module_interop_verification_matrix_"),
        "interop gate should use a repo-local namespaced rch target dir"
    );
    assert!(
        !script.contains("/tmp/rch_target_franken_engine_rgc_module_interop_matrix_"),
        "interop gate must not default heavy remote builds to /tmp"
    );
    assert!(
        script.contains("rch reported local fallback; refusing local execution for heavy command"),
        "interop gate must fail closed if rch falls back to local execution"
    );
    assert!(
        script.contains("rch output missing remote exit marker; failing closed"),
        "interop gate must fail closed if rch omits the remote exit marker"
    );
    assert!(
        !script.contains("warning: missing remote exit marker; relying on rch process exit status"),
        "interop gate must not downgrade a missing remote exit marker to a warning"
    );
}

// ===========================================================================
// Section 1: Default matrix loading and basic properties
// ===========================================================================

#[test]
fn default_matrix_loads_successfully() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert!(!m.entries().is_empty());
}

#[test]
fn default_matrix_schema_version_is_set() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert_eq!(m.schema_version, "1.0.0");
}

#[test]
fn default_matrix_round_trip_via_json_pretty() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let json = m.to_json_pretty().unwrap();
    let m2 = ModuleCompatibilityMatrix::from_json_str(&json).unwrap();
    assert_eq!(m.canonical_hash(), m2.canonical_hash());
}

#[test]
fn default_matrix_canonical_hash_deterministic() {
    let a = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let b = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert_eq!(a.canonical_hash(), b.canonical_hash());
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
}

#[test]
fn default_matrix_via_default_trait() {
    let m = ModuleCompatibilityMatrix::default();
    assert!(!m.entries().is_empty());
}

#[test]
fn default_matrix_json_constant_is_valid_json() {
    assert!(!DEFAULT_MATRIX_JSON.is_empty());
    let _m = ModuleCompatibilityMatrix::from_json_str(DEFAULT_MATRIX_JSON).unwrap();
}

#[test]
fn default_matrix_events_empty_initially() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    assert!(m.events().is_empty());
}

#[test]
fn default_matrix_has_required_waivers() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let waivers = m.required_waiver_ids();
    assert!(!waivers.is_empty());
}

// ===========================================================================
// Section 2: Enum as_str and Ord
// ===========================================================================

#[test]
fn module_feature_as_str_all_variants() {
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
fn compatibility_runtime_as_str_all_variants() {
    assert_eq!(
        CompatibilityRuntime::FrankenEngine.as_str(),
        "franken_engine"
    );
    assert_eq!(CompatibilityRuntime::Node.as_str(), "node");
    assert_eq!(CompatibilityRuntime::Bun.as_str(), "bun");
}

#[test]
fn compatibility_mode_as_str_all_variants() {
    assert_eq!(CompatibilityMode::Native.as_str(), "native");
    assert_eq!(CompatibilityMode::NodeCompat.as_str(), "node_compat");
    assert_eq!(CompatibilityMode::BunCompat.as_str(), "bun_compat");
}

#[test]
fn reference_runtime_as_str_all_variants() {
    assert_eq!(ReferenceRuntime::Node.as_str(), "node");
    assert_eq!(ReferenceRuntime::Bun.as_str(), "bun");
}

#[test]
fn module_feature_ord_is_declaration_order() {
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

#[test]
fn reference_runtime_ord() {
    assert!(ReferenceRuntime::Node < ReferenceRuntime::Bun);
}

// ===========================================================================
// Section 3: Error codes and Display
// ===========================================================================

#[test]
fn error_code_stable_codes_are_distinct() {
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
    let strs: Vec<&str> = codes.iter().map(|c| c.stable_code()).collect();
    let set: BTreeSet<&str> = strs.iter().copied().collect();
    assert_eq!(strs.len(), set.len());
}

#[test]
fn error_code_stable_code_prefix() {
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
    for code in &codes {
        assert!(
            code.stable_code().starts_with("FE-MODCOMP-"),
            "code {} does not start with FE-MODCOMP-",
            code.stable_code()
        );
    }
}

#[test]
fn error_display_without_event_includes_code_and_message() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::InvalidMatrix,
        message: "bad schema".to_string(),
        event: None,
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-MODCOMP-0007"));
    assert!(msg.contains("bad schema"));
}

#[test]
fn error_display_with_event_includes_trace_ids() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::CaseNotFound,
        message: "not found".to_string(),
        event: Some(
            frankenengine_engine::module_compatibility_matrix::CompatibilityEvent {
                seq: 0,
                trace_id: "t-abc".to_string(),
                decision_id: "d-def".to_string(),
                policy_id: "p-ghi".to_string(),
                component: "module_compatibility_matrix".to_string(),
                event: "test".to_string(),
                outcome: "deny".to_string(),
                error_code: "FE-MODCOMP-0003".to_string(),
                case_id: "case-x".to_string(),
                runtime: "node".to_string(),
                mode: "native".to_string(),
                detail: "missing case".to_string(),
            },
        ),
    };
    let msg = err.to_string();
    assert!(msg.contains("t-abc"));
    assert!(msg.contains("d-def"));
    assert!(msg.contains("p-ghi"));
}

#[test]
fn error_implements_std_error() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::InvalidMatrix,
        message: "test".to_string(),
        event: None,
    };
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// Section 4: from_entries construction validation
// ===========================================================================

#[test]
fn from_entries_empty_schema_version_fails() {
    let err = ModuleCompatibilityMatrix::from_entries("", Vec::new()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn from_entries_whitespace_only_schema_version_fails() {
    let err = ModuleCompatibilityMatrix::from_entries("   ", Vec::new()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn from_entries_empty_case_id_fails() {
    let mut e = base_entry("valid");
    e.case_id = "".to_string();
    let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![e]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn from_entries_whitespace_only_case_id_fails() {
    let mut e = base_entry("valid");
    e.case_id = "   ".to_string();
    let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![e]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn from_entries_duplicate_case_id_fails() {
    let err = ModuleCompatibilityMatrix::from_entries(
        "1.0.0",
        vec![base_entry("dup"), base_entry("dup")],
    )
    .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::DuplicateCaseId);
}

#[test]
fn from_entries_valid_single_entry() {
    let m = matrix_with(vec![base_entry("case-1")]);
    assert_eq!(m.entries().len(), 1);
}

#[test]
fn from_entries_valid_multiple_entries() {
    let m = matrix_with(vec![base_entry("a"), base_entry("b"), base_entry("c")]);
    assert_eq!(m.entries().len(), 3);
}

#[test]
fn from_json_str_invalid_json_fails() {
    let err = ModuleCompatibilityMatrix::from_json_str("{not valid json}").unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MatrixParseError);
}

// ===========================================================================
// Section 5: Entry lookup
// ===========================================================================

#[test]
fn entry_lookup_by_known_id() {
    let m = matrix_with(vec![base_entry("known-id")]);
    let e = m.entry("known-id").unwrap();
    assert_eq!(e.case_id, "known-id");
}

#[test]
fn entry_lookup_unknown_returns_none() {
    let m = matrix_with(vec![base_entry("case-1")]);
    assert!(m.entry("no-such-case").is_none());
}

#[test]
fn entries_returns_all_in_sorted_order() {
    let m = matrix_with(vec![
        base_entry("z-last"),
        base_entry("a-first"),
        base_entry("m-mid"),
    ]);
    let ids: Vec<&str> = m.entries().iter().map(|e| e.case_id.as_str()).collect();
    assert_eq!(ids, vec!["a-first", "m-mid", "z-last"]);
}

// ===========================================================================
// Section 6: validate_with_waivers - validation rules
// ===========================================================================

#[test]
fn validate_fully_matching_entry_passes() {
    let mut m = matrix_with(vec![base_entry("valid")]);
    m.validate_with_waivers(&BTreeSet::new(), &ctx()).unwrap();
    assert!(!m.events().is_empty());
}

#[test]
fn validate_empty_scenario_fails() {
    let mut e = base_entry("bad-scenario");
    e.scenario = "".to_string();
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_empty_lockstep_case_refs_fails() {
    let mut e = base_entry("no-lockstep");
    e.lockstep_case_refs.clear();
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_empty_test262_refs_fails() {
    let mut e = base_entry("no-test262");
    e.test262_refs.clear();
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

// ===========================================================================
// Section 7: Shim validation
// ===========================================================================

#[test]
fn validate_shim_with_empty_shim_id_fails() {
    let mut e = base_entry("shim-test");
    e.franken_node_compat_behavior = "different".to_string();
    let mut shim = make_shim("", CompatibilityMode::NodeCompat);
    shim.shim_id = "".to_string();
    e.explicit_shims.push(shim);
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_with_empty_description_fails() {
    let mut e = base_entry("shim-desc");
    e.franken_node_compat_behavior = "different".to_string();
    let mut shim = make_shim("shim-1", CompatibilityMode::NodeCompat);
    shim.description = "".to_string();
    e.explicit_shims.push(shim);
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_with_empty_test_case_ref_fails() {
    let mut e = base_entry("shim-ref");
    e.franken_node_compat_behavior = "different".to_string();
    let mut shim = make_shim("shim-1", CompatibilityMode::NodeCompat);
    shim.test_case_ref = "".to_string();
    e.explicit_shims.push(shim);
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_with_detached_test_case_ref_fails() {
    let mut e = base_entry("shim-detached-ref");
    e.franken_node_compat_behavior = "different".to_string();
    let mut shim = make_shim("shim-1", CompatibilityMode::NodeCompat);
    shim.test_case_ref = "lockstep/not-declared".to_string();
    e.explicit_shims.push(shim);
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn validate_shim_not_removable_fails() {
    let mut e = base_entry("shim-perm");
    e.franken_node_compat_behavior = "different".to_string();
    let mut shim = make_shim("shim-1", CompatibilityMode::NodeCompat);
    shim.removable = false;
    e.explicit_shims.push(shim);
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn duplicate_shim_id_for_same_mode_fails_during_construction() {
    let mut e = base_entry("dup-shim");
    e.franken_bun_compat_behavior = "different".to_string();
    e.explicit_shims
        .push(make_shim("shim-dup", CompatibilityMode::BunCompat));

    let mut duplicate = make_shim("  shim-dup  ", CompatibilityMode::BunCompat);
    duplicate.description = "second declaration".to_string();
    duplicate.test_case_ref = "language/module-code/integ.js".to_string();
    e.explicit_shims.push(duplicate);

    let err = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![e]).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
    assert!(err.message.contains("duplicate explicit shim_id"));
    assert!(err.message.contains("bun_compat"));
}

#[test]
fn same_shim_id_across_modes_is_still_allowed() {
    let mut e = base_entry("shared-shim-id");
    e.franken_node_compat_behavior = "node-different".to_string();
    e.franken_bun_compat_behavior = "bun-different".to_string();
    e.explicit_shims
        .push(make_shim("shim-shared", CompatibilityMode::NodeCompat));
    e.explicit_shims
        .push(make_shim("shim-shared", CompatibilityMode::BunCompat));

    let mut m = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![e]).unwrap();
    m.validate_with_waivers(&BTreeSet::new(), &ctx()).unwrap();
}

// ===========================================================================
// Section 8: Hidden shim detection
// ===========================================================================

#[test]
fn hidden_node_compat_shim_detected() {
    let mut e = base_entry("hidden-nc");
    e.franken_node_compat_behavior = "node-compat-different".to_string();
    // No shim for NodeCompat
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::HiddenShim);
}

#[test]
fn hidden_bun_compat_shim_detected() {
    let mut e = base_entry("hidden-bc");
    e.franken_bun_compat_behavior = "bun-compat-different".to_string();
    // No shim for BunCompat
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::HiddenShim);
}

#[test]
fn explicit_node_compat_shim_passes() {
    let mut e = base_entry("ok-nc-shim");
    e.franken_node_compat_behavior = "different".to_string();
    e.explicit_shims
        .push(make_shim("shim-nc", CompatibilityMode::NodeCompat));
    let mut m = matrix_with(vec![e]);
    m.validate_with_waivers(&BTreeSet::new(), &ctx()).unwrap();
}

#[test]
fn explicit_bun_compat_shim_passes() {
    let mut e = base_entry("ok-bc-shim");
    e.franken_bun_compat_behavior = "different".to_string();
    e.explicit_shims
        .push(make_shim("shim-bc", CompatibilityMode::BunCompat));
    let mut m = matrix_with(vec![e]);
    m.validate_with_waivers(&BTreeSet::new(), &ctx()).unwrap();
}

// ===========================================================================
// Section 9: Divergence policy validation
// ===========================================================================

#[test]
fn divergence_present_but_no_actual_mismatch_fails() {
    let mut e = base_entry("false-diverge");
    // All behaviors match, but divergence declared
    e.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "w-x"));
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::from(["w-x".to_string()]), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn native_diverges_from_node_without_policy_fails() {
    let mut e = base_entry("no-policy");
    e.franken_native_behavior = "native-only".to_string();
    e.franken_node_compat_behavior = "native-only".to_string();
    e.franken_bun_compat_behavior = "native-only".to_string();
    e.node_behavior = "node-different".to_string();
    e.bun_behavior = "native-only".to_string(); // bun matches native
    e.divergence = None;
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
}

#[test]
fn divergence_runtime_set_mismatch_fails() {
    let mut e = base_entry("set-mismatch");
    e.franken_native_behavior = "native".to_string();
    e.franken_node_compat_behavior = "native".to_string();
    e.franken_bun_compat_behavior = "native".to_string();
    e.node_behavior = "node-diff".to_string();
    e.bun_behavior = "bun-diff".to_string();
    // Declares only Node, but Bun also diverges
    e.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "w-1"));
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::from(["w-1".to_string()]), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::InvalidMatrix);
}

#[test]
fn divergence_with_unapproved_waiver_fails() {
    let mut e = base_entry("unapproved");
    e.franken_native_behavior = "native".to_string();
    e.franken_node_compat_behavior = "native".to_string();
    e.franken_bun_compat_behavior = "native".to_string();
    e.node_behavior = "node-diff".to_string();
    e.bun_behavior = "native".to_string(); // bun matches native, only node diverges
    e.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "w-unapproved"));
    let mut m = matrix_with(vec![e]);
    // Do not include w-unapproved in the approved set
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
}

#[test]
fn divergence_with_empty_waiver_id_fails() {
    let mut e = base_entry("empty-waiver");
    e.franken_native_behavior = "native".to_string();
    e.franken_node_compat_behavior = "native".to_string();
    e.franken_bun_compat_behavior = "native".to_string();
    e.node_behavior = "node-diff".to_string();
    e.bun_behavior = "native".to_string();
    e.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], ""));
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::new(), &ctx())
        .unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::MissingWaiver);
}

#[test]
fn divergence_with_empty_migration_guidance_fails() {
    let mut e = base_entry("no-guidance");
    e.franken_native_behavior = "native".to_string();
    e.franken_node_compat_behavior = "native".to_string();
    e.franken_bun_compat_behavior = "native".to_string();
    e.node_behavior = "node-diff".to_string();
    e.bun_behavior = "native".to_string();
    let mut dp = divergence_for(vec![ReferenceRuntime::Node], "w-ok");
    dp.migration_guidance = "".to_string();
    e.divergence = Some(dp);
    let mut m = matrix_with(vec![e]);
    let err = m
        .validate_with_waivers(&BTreeSet::from(["w-ok".to_string()]), &ctx())
        .unwrap_err();
    assert_eq!(
        err.code,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance
    );
}

#[test]
fn valid_divergence_with_approved_waiver_passes() {
    let mut e = base_entry("good-diverge");
    e.franken_native_behavior = "native-strict".to_string();
    e.franken_node_compat_behavior = "native-strict".to_string();
    e.franken_bun_compat_behavior = "native-strict".to_string();
    e.node_behavior = "node-lenient".to_string();
    e.bun_behavior = "native-strict".to_string(); // bun matches native
    e.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "w-good"));
    let mut m = matrix_with(vec![e]);
    m.validate_with_waivers(&BTreeSet::from(["w-good".to_string()]), &ctx())
        .unwrap();
}

#[test]
fn divergence_from_both_runtimes_with_correct_set_passes() {
    let mut e = base_entry("both-div");
    e.franken_native_behavior = "franken-only".to_string();
    e.franken_node_compat_behavior = "franken-only".to_string();
    e.franken_bun_compat_behavior = "franken-only".to_string();
    e.node_behavior = "node-way".to_string();
    e.bun_behavior = "bun-way".to_string();
    e.divergence = Some(divergence_for(
        vec![ReferenceRuntime::Node, ReferenceRuntime::Bun],
        "w-both",
    ));
    let mut m = matrix_with(vec![e]);
    m.validate_with_waivers(&BTreeSet::from(["w-both".to_string()]), &ctx())
        .unwrap();
}

// ===========================================================================
// Section 10: evaluate_observation
// ===========================================================================

#[test]
fn observation_matching_native_behavior_succeeds() {
    let mut m = matrix_with(vec![base_entry("obs-ok")]);
    let obs = CompatibilityObservation::new(
        "obs-ok",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "ok",
    );
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
    assert_eq!(outcome.expected_behavior, "ok");
    assert_eq!(outcome.observed_behavior, "ok");
    assert!(outcome.divergence.is_none());
}

#[test]
fn observation_mismatch_fails_with_error() {
    let mut m = matrix_with(vec![base_entry("obs-fail")]);
    let obs = CompatibilityObservation::new(
        "obs-fail",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "wrong-behavior",
    );
    let err = m.evaluate_observation(&obs, &ctx()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::ObservationMismatch);
    assert!(err.message.contains("mismatch"));
}

#[test]
fn observation_unknown_case_fails() {
    let mut m = matrix_with(vec![base_entry("exists")]);
    let obs = CompatibilityObservation::new(
        "does-not-exist",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "whatever",
    );
    let err = m.evaluate_observation(&obs, &ctx()).unwrap_err();
    assert_eq!(err.code, CompatibilityMatrixErrorCode::CaseNotFound);
}

#[test]
fn observation_node_runtime_checks_node_behavior() {
    let mut e = base_entry("node-obs");
    e.node_behavior = "node-specific".to_string();
    let mut m = matrix_with(vec![e]);
    let obs = CompatibilityObservation::new(
        "node-obs",
        CompatibilityRuntime::Node,
        CompatibilityMode::Native,
        "node-specific",
    );
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
}

#[test]
fn observation_bun_runtime_checks_bun_behavior() {
    let mut e = base_entry("bun-obs");
    e.bun_behavior = "bun-specific".to_string();
    let mut m = matrix_with(vec![e]);
    let obs = CompatibilityObservation::new(
        "bun-obs",
        CompatibilityRuntime::Bun,
        CompatibilityMode::Native,
        "bun-specific",
    );
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
}

#[test]
fn observation_franken_node_compat_checks_correct_field() {
    let mut e = base_entry("nc-obs");
    e.franken_node_compat_behavior = "nc-behavior".to_string();
    let mut m = matrix_with(vec![e]);
    let obs = CompatibilityObservation::new(
        "nc-obs",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::NodeCompat,
        "nc-behavior",
    );
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
}

#[test]
fn observation_franken_bun_compat_checks_correct_field() {
    let mut e = base_entry("bc-obs");
    e.franken_bun_compat_behavior = "bc-behavior".to_string();
    let mut m = matrix_with(vec![e]);
    let obs = CompatibilityObservation::new(
        "bc-obs",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::BunCompat,
        "bc-behavior",
    );
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
}

#[test]
fn observation_outcome_includes_divergence_policy_when_present() {
    let mut e = base_entry("div-obs");
    e.franken_native_behavior = "native-val".to_string();
    e.node_behavior = "node-val".to_string();
    e.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "w-div-obs"));
    let mut m = matrix_with(vec![e]);
    let obs = CompatibilityObservation::new(
        "div-obs",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "native-val",
    );
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
    assert!(outcome.divergence.is_some());
    assert_eq!(outcome.divergence.unwrap().waiver_id, "w-div-obs");
}

#[test]
fn observation_trims_whitespace_from_observed() {
    let mut m = matrix_with(vec![base_entry("trim-obs")]);
    let obs = CompatibilityObservation::new(
        "trim-obs",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "  ok  ",
    );
    // The entry has franken_native_behavior = "ok", and observed " ok " trims to "ok"
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
}

// ===========================================================================
// Section 11: Event sequencing and audit
// ===========================================================================

#[test]
fn events_have_sequential_seq_numbers() {
    let mut m = matrix_with(vec![base_entry("e1"), base_entry("e2"), base_entry("e3")]);
    m.validate_with_waivers(&BTreeSet::new(), &ctx()).unwrap();
    let events = m.events();
    assert!(events.len() >= 3);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.seq, i as u64);
    }
}

#[test]
fn events_carry_context_trace_and_decision_ids() {
    let mut m = matrix_with(vec![base_entry("ctx-check")]);
    let custom_ctx = CompatibilityContext::new("my-trace", "my-decision", "my-policy");
    m.validate_with_waivers(&BTreeSet::new(), &custom_ctx)
        .unwrap();
    let event = &m.events()[0];
    assert_eq!(event.trace_id, "my-trace");
    assert_eq!(event.decision_id, "my-decision");
    assert_eq!(event.policy_id, "my-policy");
}

#[test]
fn events_carry_component_name() {
    let mut m = matrix_with(vec![base_entry("comp-check")]);
    m.validate_with_waivers(&BTreeSet::new(), &ctx()).unwrap();
    assert_eq!(m.events()[0].component, "module_compatibility_matrix");
}

#[test]
fn validation_events_accumulate_across_operations() {
    let mut m = matrix_with(vec![base_entry("accum")]);
    m.validate_with_waivers(&BTreeSet::new(), &ctx()).unwrap();
    let first_count = m.events().len();

    let obs = CompatibilityObservation::new(
        "accum",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "ok",
    );
    m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(m.events().len() > first_count);
}

#[test]
fn error_events_also_accumulate() {
    let mut m = matrix_with(vec![base_entry("err-accum")]);
    let bad_obs = CompatibilityObservation::new(
        "does-not-exist",
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        "whatever",
    );
    let _ = m.evaluate_observation(&bad_obs, &ctx());
    assert!(!m.events().is_empty());
    let last = m.events().last().unwrap();
    assert_eq!(last.outcome, "deny");
}

// ===========================================================================
// Section 12: Canonical hash sensitivity
// ===========================================================================

#[test]
fn canonical_hash_differs_for_different_case_ids() {
    let a = matrix_with(vec![base_entry("alpha")]);
    let b = matrix_with(vec![base_entry("beta")]);
    assert_ne!(a.canonical_hash(), b.canonical_hash());
}

#[test]
fn canonical_hash_differs_for_different_schema_versions() {
    let a = ModuleCompatibilityMatrix::from_entries("1.0.0", vec![base_entry("same")]).unwrap();
    let b = ModuleCompatibilityMatrix::from_entries("2.0.0", vec![base_entry("same")]).unwrap();
    assert_ne!(a.canonical_hash(), b.canonical_hash());
}

#[test]
fn canonical_hash_differs_for_different_features() {
    let mut e1 = base_entry("feat-test");
    e1.feature = ModuleFeature::Esm;
    let mut e2 = base_entry("feat-test");
    e2.feature = ModuleFeature::Cjs;
    let a = matrix_with(vec![e1]);
    let b = matrix_with(vec![e2]);
    assert_ne!(a.canonical_hash(), b.canonical_hash());
}

#[test]
fn canonical_hash_stable_across_repeated_calls() {
    let m = matrix_with(vec![base_entry("stable")]);
    let h1 = m.canonical_hash();
    let h2 = m.canonical_hash();
    let h3 = m.canonical_hash();
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

// ===========================================================================
// Section 13: Serde round-trips
// ===========================================================================

#[test]
fn module_feature_serde_round_trip() {
    for variant in [
        ModuleFeature::Esm,
        ModuleFeature::Cjs,
        ModuleFeature::DualMode,
        ModuleFeature::ConditionalExports,
        ModuleFeature::PackageJsonFields,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ModuleFeature = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn compatibility_runtime_serde_round_trip() {
    for variant in [
        CompatibilityRuntime::FrankenEngine,
        CompatibilityRuntime::Node,
        CompatibilityRuntime::Bun,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: CompatibilityRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn compatibility_mode_serde_round_trip() {
    for variant in [
        CompatibilityMode::Native,
        CompatibilityMode::NodeCompat,
        CompatibilityMode::BunCompat,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: CompatibilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn reference_runtime_serde_round_trip() {
    for variant in [ReferenceRuntime::Node, ReferenceRuntime::Bun] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ReferenceRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn error_code_serde_round_trip() {
    for variant in [
        CompatibilityMatrixErrorCode::MatrixParseError,
        CompatibilityMatrixErrorCode::DuplicateCaseId,
        CompatibilityMatrixErrorCode::CaseNotFound,
        CompatibilityMatrixErrorCode::HiddenShim,
        CompatibilityMatrixErrorCode::MissingWaiver,
        CompatibilityMatrixErrorCode::MissingMigrationGuidance,
        CompatibilityMatrixErrorCode::InvalidMatrix,
        CompatibilityMatrixErrorCode::ObservationMismatch,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: CompatibilityMatrixErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

#[test]
fn explicit_shim_serde_round_trip() {
    let shim = make_shim("shim-serde", CompatibilityMode::NodeCompat);
    let json = serde_json::to_string(&shim).unwrap();
    let back: ExplicitShim = serde_json::from_str(&json).unwrap();
    assert_eq!(shim, back);
}

#[test]
fn divergence_policy_serde_round_trip() {
    let dp = divergence_for(
        vec![ReferenceRuntime::Node, ReferenceRuntime::Bun],
        "w-serde",
    );
    let json = serde_json::to_string(&dp).unwrap();
    let back: DivergencePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(dp, back);
}

#[test]
fn compatibility_entry_serde_round_trip() {
    let e = base_entry("serde-entry");
    let json = serde_json::to_string(&e).unwrap();
    let back: CompatibilityMatrixEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn compatibility_context_serde_round_trip() {
    let c = ctx();
    let json = serde_json::to_string(&c).unwrap();
    let back: CompatibilityContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn compatibility_observation_serde_round_trip() {
    let obs = CompatibilityObservation::new(
        "serde-obs",
        CompatibilityRuntime::Bun,
        CompatibilityMode::BunCompat,
        "observed",
    );
    let json = serde_json::to_string(&obs).unwrap();
    let back: CompatibilityObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn compatibility_matrix_error_serde_round_trip() {
    let err = CompatibilityMatrixError {
        code: CompatibilityMatrixErrorCode::CaseNotFound,
        message: "serde test".to_string(),
        event: None,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: CompatibilityMatrixError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ===========================================================================
// Section 14: required_waiver_ids
// ===========================================================================

#[test]
fn required_waiver_ids_empty_when_no_divergences() {
    let m = matrix_with(vec![base_entry("no-div")]);
    assert!(m.required_waiver_ids().is_empty());
}

#[test]
fn required_waiver_ids_deduplicates() {
    let mut e1 = base_entry("div-a");
    e1.franken_native_behavior = "a".to_string();
    e1.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "shared"));

    let mut e2 = base_entry("div-b");
    e2.franken_native_behavior = "b".to_string();
    e2.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "shared"));

    let m = matrix_with(vec![e1, e2]);
    let waivers = m.required_waiver_ids();
    assert_eq!(waivers.len(), 1);
    assert!(waivers.contains("shared"));
}

#[test]
fn required_waiver_ids_collects_distinct() {
    let mut e1 = base_entry("div-x");
    e1.franken_native_behavior = "x".to_string();
    e1.divergence = Some(divergence_for(vec![ReferenceRuntime::Node], "waiver-x"));

    let mut e2 = base_entry("div-y");
    e2.franken_native_behavior = "y".to_string();
    e2.divergence = Some(divergence_for(vec![ReferenceRuntime::Bun], "waiver-y"));

    let m = matrix_with(vec![e1, e2]);
    let waivers = m.required_waiver_ids();
    assert_eq!(waivers.len(), 2);
    assert!(waivers.contains("waiver-x"));
    assert!(waivers.contains("waiver-y"));
}

// ===========================================================================
// Section 15: Normalization and edge cases
// ===========================================================================

#[test]
fn entry_whitespace_trimmed_on_construction() {
    let mut e = base_entry("  trimmed  ");
    e.scenario = "  spaced scenario  ".to_string();
    e.node_behavior = "  node  ".to_string();
    let m = matrix_with(vec![e]);
    let entry = m.entry("trimmed").unwrap();
    assert_eq!(entry.case_id, "trimmed");
    assert_eq!(entry.scenario, "spaced scenario");
    assert_eq!(entry.node_behavior, "node");
}

#[test]
fn lockstep_refs_normalized_and_deduped() {
    let mut e = base_entry("dedup-refs");
    e.lockstep_case_refs = vec![
        "  ref-b  ".to_string(),
        "ref-a".to_string(),
        "ref-b".to_string(),
    ];
    let m = matrix_with(vec![e]);
    let entry = m.entry("dedup-refs").unwrap();
    assert_eq!(entry.lockstep_case_refs, vec!["ref-a", "ref-b"]);
}

#[test]
fn test262_refs_normalized_and_deduped() {
    let mut e = base_entry("dedup-t262");
    e.test262_refs = vec![
        "  z-test.js  ".to_string(),
        "a-test.js".to_string(),
        "z-test.js".to_string(),
    ];
    let m = matrix_with(vec![e]);
    let entry = m.entry("dedup-t262").unwrap();
    assert_eq!(entry.test262_refs, vec!["a-test.js", "z-test.js"]);
}

#[test]
fn empty_lockstep_refs_after_normalization_removed() {
    let mut e = base_entry("empty-after-trim");
    e.lockstep_case_refs = vec!["  ".to_string(), "".to_string(), "real-ref".to_string()];
    let m = matrix_with(vec![e]);
    let entry = m.entry("empty-after-trim").unwrap();
    assert_eq!(entry.lockstep_case_refs, vec!["real-ref"]);
}

// ===========================================================================
// Section 16: Default matrix validation with real waivers
// ===========================================================================

#[test]
fn default_matrix_validates_with_all_required_waivers() {
    let mut m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let required = m.required_waiver_ids();
    m.validate_with_waivers(&required, &ctx()).unwrap();
    assert!(!m.events().is_empty());
}

#[test]
fn default_matrix_observations_against_known_entries() {
    let mut m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    // Check the first entry from the default JSON
    let entries = m.entries();
    let first = entries[0].clone();
    let obs = CompatibilityObservation::new(
        first.case_id.clone(),
        CompatibilityRuntime::FrankenEngine,
        CompatibilityMode::Native,
        first.franken_native_behavior.clone(),
    );
    let outcome = m.evaluate_observation(&obs, &ctx()).unwrap();
    assert!(outcome.matched);
}

#[test]
fn default_matrix_all_entries_have_case_ids_and_scenarios() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    for entry in m.entries() {
        assert!(!entry.case_id.is_empty());
        assert!(!entry.scenario.is_empty());
    }
}

#[test]
fn default_matrix_includes_cyclic_import_edge_case() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let entry = m
        .entry("esm-cjs-cycle-live-binding")
        .expect("default matrix should include cyclic interop edge");
    assert_eq!(entry.feature, ModuleFeature::DualMode);
    assert!(entry.scenario.to_ascii_lowercase().contains("cyclic"));
}

#[test]
fn default_matrix_pins_mixed_cycle_contract_and_bun_shim() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let entry = m
        .entry("esm-cjs-cycle-live-binding")
        .expect("default matrix should include mixed cycle case");

    assert_eq!(entry.feature, ModuleFeature::DualMode);
    assert_eq!(entry.node_behavior, "throw_err_require_esm");
    assert_eq!(entry.bun_behavior, "preserve_live_bindings_through_cycle");
    assert_eq!(entry.franken_native_behavior, "throw_err_require_esm");
    assert_eq!(entry.franken_node_compat_behavior, "throw_err_require_esm");
    assert_eq!(
        entry.franken_bun_compat_behavior,
        "preserve_live_bindings_through_cycle"
    );
    assert_eq!(entry.explicit_shims.len(), 1);
    assert_eq!(
        entry.explicit_shims[0].shim_id,
        "shim-bun-esm-cjs-cycle-live-binding-v1"
    );
    assert_eq!(entry.explicit_shims[0].mode, CompatibilityMode::BunCompat);
    assert!(
        entry
            .lockstep_case_refs
            .contains(&"lockstep/module/esm-cjs-cycle-live-binding".to_string())
    );

    let divergence = entry
        .divergence
        .as_ref()
        .expect("mixed-cycle case must record the Bun divergence explicitly");
    assert_eq!(divergence.diverges_from, vec![ReferenceRuntime::Bun]);
    assert_eq!(
        divergence.waiver_id,
        "waiver-modcomp-esm-cjs-cycle-live-binding-bun"
    );
    assert!(
        divergence.migration_guidance.contains("bun_compat")
            && divergence.migration_guidance.contains("dynamic import()"),
        "mixed-cycle divergence should carry actionable migration guidance"
    );
}

#[test]
fn default_matrix_pins_require_of_esm_contract_and_bun_shim() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let entry = m
        .entry("cjs-require-esm")
        .expect("default matrix should include require-of-esm case");

    assert_eq!(entry.feature, ModuleFeature::Cjs);
    assert_eq!(entry.node_behavior, "throw_err_require_esm");
    assert_eq!(entry.bun_behavior, "allow_via_sync_bridge");
    assert_eq!(entry.franken_native_behavior, "throw_err_require_esm");
    assert_eq!(entry.franken_node_compat_behavior, "throw_err_require_esm");
    assert_eq!(entry.franken_bun_compat_behavior, "allow_via_sync_bridge");
    assert_eq!(entry.explicit_shims.len(), 1);
    assert_eq!(
        entry.explicit_shims[0].shim_id,
        "shim-bun-cjs-require-esm-bridge-v1"
    );
    assert_eq!(entry.explicit_shims[0].mode, CompatibilityMode::BunCompat);
    assert!(
        entry
            .lockstep_case_refs
            .contains(&"lockstep/module/cjs-require-esm".to_string())
    );

    let divergence = entry
        .divergence
        .as_ref()
        .expect("require-of-esm case must record the Bun divergence explicitly");
    assert_eq!(divergence.diverges_from, vec![ReferenceRuntime::Bun]);
    assert_eq!(divergence.waiver_id, "waiver-modcomp-cjs-require-esm-bun");
    assert!(
        divergence.migration_guidance.contains("dynamic import()")
            && divergence.migration_guidance.contains("bun_compat"),
        "require-of-esm divergence should carry actionable migration guidance"
    );
}

#[test]
fn default_matrix_pins_exports_map_contracts() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();

    let conditional = m
        .entry("conditional-exports-condition-order")
        .expect("default matrix should include conditional exports ordering case");
    assert_eq!(conditional.feature, ModuleFeature::ConditionalExports);
    assert_eq!(
        conditional.node_behavior,
        "resolve_condition_import_require_default"
    );
    assert_eq!(
        conditional.franken_native_behavior,
        "resolve_condition_import_require_default"
    );
    assert!(conditional.explicit_shims.is_empty());
    assert!(
        conditional
            .lockstep_case_refs
            .contains(&"lockstep/module/conditional-exports-condition-order".to_string())
    );

    let dual_mode = m
        .entry("dual-mode-exports-map")
        .expect("default matrix should include dual-mode exports map case");
    assert_eq!(dual_mode.feature, ModuleFeature::DualMode);
    assert_eq!(dual_mode.node_behavior, "resolve_exports_by_import_style");
    assert_eq!(
        dual_mode.franken_node_compat_behavior,
        "resolve_exports_by_import_style"
    );
    assert_eq!(
        dual_mode.franken_bun_compat_behavior,
        "resolve_exports_by_import_style"
    );
    assert!(dual_mode.explicit_shims.is_empty());
    assert!(
        dual_mode
            .lockstep_case_refs
            .contains(&"lockstep/module/dual-mode-exports-map".to_string())
    );
}

#[test]
fn default_matrix_pins_default_namespace_projection_contract() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let entry = m
        .entry("esm-import-cjs-default")
        .expect("default matrix should include ESM-imports-CJS default projection case");

    assert_eq!(entry.feature, ModuleFeature::Esm);
    assert_eq!(entry.node_behavior, "namespace_default_projection");
    assert_eq!(entry.bun_behavior, "namespace_default_projection");
    assert_eq!(
        entry.franken_native_behavior,
        "namespace_default_projection"
    );
    assert_eq!(
        entry.franken_node_compat_behavior,
        "namespace_default_projection"
    );
    assert_eq!(
        entry.franken_bun_compat_behavior,
        "namespace_default_projection"
    );
    assert!(entry.explicit_shims.is_empty());
    assert!(
        entry
            .lockstep_case_refs
            .contains(&"lockstep/module/esm-import-cjs-default".to_string())
    );
    assert!(entry.divergence.is_none());
}

#[test]
fn default_matrix_pins_extensionless_relative_esm_contract() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let entry = m
        .entry("package-type-module-extensionless-relative")
        .expect("default matrix should include extensionless-relative ESM case");
    assert_eq!(entry.feature, ModuleFeature::PackageJsonFields);
    assert_eq!(entry.node_behavior, "reject_extensionless_relative");
    assert_eq!(entry.bun_behavior, "resolve_extensionless_relative");
    assert_eq!(
        entry.franken_native_behavior,
        "reject_extensionless_relative"
    );
    assert_eq!(
        entry.franken_node_compat_behavior,
        "reject_extensionless_relative"
    );
    assert_eq!(
        entry.franken_bun_compat_behavior,
        "resolve_extensionless_relative"
    );
    assert!(
        entry
            .lockstep_case_refs
            .contains(&"lockstep/module/package-type-module-extensionless-relative".to_string())
    );
}

#[test]
fn default_matrix_pins_external_extension_probe_package_root_contract() {
    let m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let entry = m
        .entry("external-extension-probe-package-root-relative-require")
        .expect("default matrix should include external extension-probe package-root case");
    assert_eq!(entry.feature, ModuleFeature::Cjs);
    assert_eq!(
        entry.node_behavior,
        "resolve_relative_require_from_package_root"
    );
    assert_eq!(
        entry.bun_behavior,
        "resolve_relative_require_from_package_root"
    );
    assert_eq!(
        entry.franken_native_behavior,
        "resolve_relative_require_from_package_root"
    );
    assert_eq!(
        entry.franken_node_compat_behavior,
        "resolve_relative_require_from_package_root"
    );
    assert_eq!(
        entry.franken_bun_compat_behavior,
        "resolve_relative_require_from_package_root"
    );
    assert!(entry.explicit_shims.is_empty());
    assert!(entry.lockstep_case_refs.contains(
        &"lockstep/module/external-extension-probe-package-root-relative-require".to_string()
    ));
    assert!(
        entry.lockstep_case_refs.contains(
            &"lockstep/module/scoped-external-extension-probe-package-root-relative-require"
                .to_string()
        )
    );
    assert!(
        entry
            .scenario
            .contains("package root rather than a synthetic entry-file directory")
    );
    assert!(entry.divergence.is_none());
}

#[test]
fn scenario_report_summarizes_divergence_categories_and_guidance() {
    let mut m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let required = m.required_waiver_ids();
    m.validate_with_waivers(&required, &ctx()).unwrap();

    let report = m
        .evaluate_scenario(
            "pkg-esm-cjs-edge-matrix",
            &[
                CompatibilityObservation::new(
                    "cjs-require-esm",
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    "throw_err_require_esm",
                ),
                CompatibilityObservation::new(
                    "conditional-exports-condition-order",
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    "resolve_condition_import_require_default",
                ),
                CompatibilityObservation::new(
                    "esm-cjs-cycle-live-binding",
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::BunCompat,
                    "preserve_live_bindings_through_cycle",
                ),
            ],
            &ctx(),
            1_726_000_000_001,
        )
        .expect("scenario report generation should succeed");

    assert_eq!(
        report.schema_version,
        COMPATIBILITY_SCENARIO_REPORT_SCHEMA_VERSION
    );
    assert_eq!(report.scenario_id, "pkg-esm-cjs-edge-matrix");
    assert_eq!(report.total_observations, 3);
    assert_eq!(report.matched_observations, 3);
    assert_eq!(
        report
            .divergence_category_counts
            .get("intentional_improvement")
            .copied(),
        Some(2)
    );
    assert!(
        report
            .actionable_guidance
            .contains_key("intentional_improvement")
    );
}

#[test]
fn mixed_cycle_bun_compat_interop_evidence_matches_matrix_contract() {
    let mut m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let required = m.required_waiver_ids();
    m.validate_with_waivers(&required, &ctx()).unwrap();

    let evidence = run_interop_parity_corpus()
        .evidence
        .into_iter()
        .find(|ev| ev.specimen_id == "cycle_mixed_esm_cjs")
        .expect("mixed cycle specimen should exist");
    assert_eq!(evidence.compatibility_mode, CompatibilityMode::BunCompat);
    assert_eq!(evidence.actual_outcome, InteropActualOutcome::Success);
    assert!(evidence.binding_verdicts.iter().all(|verdict| verdict.pass));

    let outcome = m
        .evaluate_observation(
            &CompatibilityObservation::new(
                "esm-cjs-cycle-live-binding",
                CompatibilityRuntime::FrankenEngine,
                CompatibilityMode::BunCompat,
                "preserve_live_bindings_through_cycle",
            ),
            &ctx(),
        )
        .expect("mixed-cycle interop evidence should match the matrix contract");
    assert!(outcome.matched);
}

#[test]
fn extensionless_relative_interop_evidence_matches_matrix_contract_across_modes() {
    let mut m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let required = m.required_waiver_ids();
    m.validate_with_waivers(&required, &ctx()).unwrap();

    let inventory = run_interop_parity_corpus();
    for (specimen_id, mode, expected_outcome, expected_behavior) in [
        (
            "package_type_module_extensionless_relative_native",
            CompatibilityMode::Native,
            InteropActualOutcome::LinkFailure,
            "reject_extensionless_relative",
        ),
        (
            "package_type_module_extensionless_relative_node_compat",
            CompatibilityMode::NodeCompat,
            InteropActualOutcome::LinkFailure,
            "reject_extensionless_relative",
        ),
        (
            "package_type_module_extensionless_relative_bun_compat",
            CompatibilityMode::BunCompat,
            InteropActualOutcome::Success,
            "resolve_extensionless_relative",
        ),
    ] {
        let evidence = inventory
            .evidence
            .iter()
            .find(|ev| ev.specimen_id == specimen_id)
            .unwrap_or_else(|| {
                panic!("extensionless-relative specimen should exist: {specimen_id}")
            });
        assert_eq!(evidence.compatibility_mode, mode);
        assert_eq!(evidence.actual_outcome, expected_outcome);

        let outcome = m
            .evaluate_observation(
                &CompatibilityObservation::new(
                    "package-type-module-extensionless-relative",
                    CompatibilityRuntime::FrankenEngine,
                    mode,
                    expected_behavior,
                ),
                &ctx(),
            )
            .unwrap_or_else(|err| {
                panic!(
                    "extensionless-relative evidence should evaluate against the matrix for {specimen_id}: {err}"
                )
            });
        assert!(
            outcome.matched,
            "extensionless-relative evidence should match the matrix contract for {specimen_id}"
        );
    }
}

#[test]
fn default_and_namespace_cjs_projection_evidence_match_matrix_contract() {
    let mut m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let required = m.required_waiver_ids();
    m.validate_with_waivers(&required, &ctx()).unwrap();

    let inventory = run_interop_parity_corpus();
    for specimen_id in ["esm_imports_cjs_default", "namespace_import_from_cjs"] {
        let evidence = inventory
            .evidence
            .iter()
            .find(|ev| ev.specimen_id == specimen_id)
            .unwrap_or_else(|| {
                panic!("default/namespace projection specimen should exist: {specimen_id}")
            });
        assert_eq!(evidence.compatibility_mode, CompatibilityMode::Native);
        assert_eq!(evidence.actual_outcome, InteropActualOutcome::Success);
        assert_eq!(
            evidence.compatibility_disposition,
            InteropCompatibilityDisposition::Supported
        );
        assert!(evidence.error_detail.is_none());
        assert!(evidence.binding_verdicts.iter().all(|verdict| verdict.pass));

        let outcome = m
            .evaluate_observation(
                &CompatibilityObservation::new(
                    "esm-import-cjs-default",
                    CompatibilityRuntime::FrankenEngine,
                    CompatibilityMode::Native,
                    "namespace_default_projection",
                ),
                &ctx(),
            )
            .unwrap_or_else(|err| {
                panic!(
                    "default/namespace projection evidence should evaluate against the matrix for {specimen_id}: {err}"
                )
            });
        assert!(
            outcome.matched,
            "default/namespace projection evidence should match the matrix contract for {specimen_id}"
        );
    }
}

#[test]
fn external_package_root_require_evidence_matches_matrix_contract_across_modes() {
    let mut m = ModuleCompatibilityMatrix::from_default_json().unwrap();
    let required = m.required_waiver_ids();
    m.validate_with_waivers(&required, &ctx()).unwrap();

    let inventory = run_interop_parity_corpus();
    for (specimen_id, mode) in [
        (
            "external_extension_probe_package_root_require_native",
            CompatibilityMode::Native,
        ),
        (
            "external_extension_probe_package_root_require_node_compat",
            CompatibilityMode::NodeCompat,
        ),
        (
            "external_extension_probe_package_root_require_bun_compat",
            CompatibilityMode::BunCompat,
        ),
        (
            "scoped_external_extension_probe_package_root_require_native",
            CompatibilityMode::Native,
        ),
        (
            "scoped_external_extension_probe_package_root_require_node_compat",
            CompatibilityMode::NodeCompat,
        ),
        (
            "scoped_external_extension_probe_package_root_require_bun_compat",
            CompatibilityMode::BunCompat,
        ),
    ] {
        let evidence = inventory
            .evidence
            .iter()
            .find(|ev| ev.specimen_id == specimen_id)
            .unwrap_or_else(|| {
                panic!("external package-root require specimen should exist: {specimen_id}")
            });
        assert_eq!(evidence.compatibility_mode, mode);
        assert_eq!(evidence.actual_outcome, InteropActualOutcome::Success);
        assert_eq!(
            evidence.compatibility_disposition,
            InteropCompatibilityDisposition::Supported
        );
        assert_eq!(evidence.linked_count, 3);
        assert!(evidence.error_detail.is_none());
        assert!(evidence.binding_verdicts.iter().all(|verdict| verdict.pass));

        let outcome = m
            .evaluate_observation(
                &CompatibilityObservation::new(
                    "external-extension-probe-package-root-relative-require",
                    CompatibilityRuntime::FrankenEngine,
                    mode,
                    "resolve_relative_require_from_package_root",
                ),
                &ctx(),
            )
            .unwrap_or_else(|err| {
                panic!(
                    "external package-root require evidence should evaluate against the matrix for {specimen_id}: {err}"
                )
            });
        assert!(
            outcome.matched,
            "external package-root require evidence should match the matrix contract for {specimen_id}"
        );
    }
}
