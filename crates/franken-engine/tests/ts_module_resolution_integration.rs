#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ts_module_resolution::{
    classify_resolution_drift, write_ts_resolution_artifacts, DeterministicTsModuleResolver,
    TsModuleRequest, TsModuleResolutionConfig, TsModuleResolutionError,
    TsModuleResolutionMode, TsModuleResolutionOutcome, TsPackageDefinition,
    TsPackageExportTarget, TsRequestStyle, TsResolutionArtifactPaths, TsResolutionContext,
    TsResolutionDriftClass, TsResolutionDriftReport, TsResolutionErrorCode,
    TsResolutionRunManifest, TsResolutionTraceEvent,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx() -> TsResolutionContext {
    TsResolutionContext::new("trace-int", "decision-int", "policy-int")
}

#[allow(dead_code)]
fn default_config() -> TsModuleResolutionConfig {
    TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        ..Default::default()
    }
}

fn resolver_with_root(root: &str) -> DeterministicTsModuleResolver {
    DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: root.to_string(),
        ..Default::default()
    })
}

fn import_req(specifier: &str) -> TsModuleRequest {
    TsModuleRequest::new(specifier, TsRequestStyle::Import)
}

fn require_req(specifier: &str) -> TsModuleRequest {
    TsModuleRequest::new(specifier, TsRequestStyle::Require)
}

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frx_tsres_int_{label}_{}_{}",
        std::process::id(),
        nanos,
    ))
}

fn make_export_target(conditions: &[(&str, &str)], fallback: Option<&str>) -> TsPackageExportTarget {
    let mut condition_targets = BTreeMap::new();
    for (k, v) in conditions {
        condition_targets.insert(k.to_string(), v.to_string());
    }
    TsPackageExportTarget {
        condition_targets,
        fallback_target: fallback.map(|s| s.to_string()),
    }
}

// ===========================================================================
// Section 1: Type construction and defaults
// ===========================================================================

#[test]
fn resolution_mode_default_is_node_next() {
    assert_eq!(
        TsModuleResolutionMode::default(),
        TsModuleResolutionMode::NodeNext,
    );
}

#[test]
fn config_default_project_root_is_slash() {
    let cfg = TsModuleResolutionConfig::default();
    assert_eq!(cfg.project_root, "/");
}

#[test]
fn config_default_base_url_is_dot() {
    let cfg = TsModuleResolutionConfig::default();
    assert_eq!(cfg.base_url, ".");
}

#[test]
fn config_default_import_extensions_order() {
    let cfg = TsModuleResolutionConfig::default();
    // .ts must come before .js for TypeScript-first probing
    let ts_pos = cfg.import_extensions.iter().position(|e| e == ".ts");
    let js_pos = cfg.import_extensions.iter().position(|e| e == ".js");
    assert!(ts_pos.unwrap() < js_pos.unwrap());
}

#[test]
fn config_default_require_extensions_include_cts() {
    let cfg = TsModuleResolutionConfig::default();
    assert!(cfg.require_extensions.contains(&".cts".to_string()));
    assert!(cfg.require_extensions.contains(&".cjs".to_string()));
}

#[test]
fn config_default_import_conditions_include_types() {
    let cfg = TsModuleResolutionConfig::default();
    assert!(cfg.import_conditions.contains(&"types".to_string()));
}

#[test]
fn resolution_context_fields_match() {
    let ctx = TsResolutionContext::new("t1", "d1", "p1");
    assert_eq!(ctx.trace_id, "t1");
    assert_eq!(ctx.decision_id, "d1");
    assert_eq!(ctx.policy_id, "p1");
}

#[test]
fn module_request_builder_chain() {
    let req = TsModuleRequest::new("./foo", TsRequestStyle::Import)
        .with_referrer("/src/bar.ts");
    assert_eq!(req.specifier, "./foo");
    assert_eq!(req.referrer.as_deref(), Some("/src/bar.ts"));
    assert_eq!(req.style, TsRequestStyle::Import);
}

// ===========================================================================
// Section 2: Serde round-trips for all public types
// ===========================================================================

#[test]
fn serde_roundtrip_resolution_mode_all_variants() {
    for mode in [
        TsModuleResolutionMode::Node16,
        TsModuleResolutionMode::NodeNext,
        TsModuleResolutionMode::Bundler,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: TsModuleResolutionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn serde_roundtrip_request_style() {
    for style in [TsRequestStyle::Import, TsRequestStyle::Require] {
        let json = serde_json::to_string(&style).unwrap();
        let back: TsRequestStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(style, back);
    }
}

#[test]
fn serde_roundtrip_resolution_context() {
    let ctx = TsResolutionContext::new("trace-x", "dec-x", "pol-x");
    let json = serde_json::to_string(&ctx).unwrap();
    let back: TsResolutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn serde_roundtrip_module_request() {
    let req = import_req("./test").with_referrer("/src/a.ts");
    let json = serde_json::to_string(&req).unwrap();
    let back: TsModuleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn serde_roundtrip_config_with_paths() {
    let mut paths = BTreeMap::new();
    paths.insert("@app/*".to_string(), vec!["src/app/*".to_string()]);
    let cfg = TsModuleResolutionConfig {
        project_root: "/ws".to_string(),
        base_url: "src".to_string(),
        mode: TsModuleResolutionMode::Bundler,
        paths,
        ..Default::default()
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: TsModuleResolutionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn serde_roundtrip_package_export_target() {
    let target = make_export_target(
        &[("import", "./dist/esm.mjs"), ("require", "./dist/cjs.cjs")],
        Some("./dist/default.js"),
    );
    let json = serde_json::to_string(&target).unwrap();
    let back: TsPackageExportTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(target, back);
}

#[test]
fn serde_roundtrip_package_definition() {
    let pkg = TsPackageDefinition::new("@scope/ui", "/nm/@scope/ui")
        .with_export(".", make_export_target(&[("import", "./index.mjs")], None));
    let json = serde_json::to_string(&pkg).unwrap();
    let back: TsPackageDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, back);
}

#[test]
fn serde_roundtrip_trace_event() {
    let event = TsResolutionTraceEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "ts_module_resolver".to_string(),
        event: "extension_probe".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
        detail: "resolved".to_string(),
        candidate: Some("/a.ts".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: TsResolutionTraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_error_code_all_variants() {
    for code in [
        TsResolutionErrorCode::EmptySpecifier,
        TsResolutionErrorCode::MissingReferrer,
        TsResolutionErrorCode::InvalidReferrer,
        TsResolutionErrorCode::PackageResolutionFailed,
        TsResolutionErrorCode::ModuleNotFound,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let back: TsResolutionErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

#[test]
fn serde_roundtrip_resolution_error() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::ModuleNotFound,
        message: "not found".to_string(),
        traces: vec![],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TsModuleResolutionError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn serde_roundtrip_resolution_outcome() {
    let outcome = TsModuleResolutionOutcome {
        request_specifier: "react".to_string(),
        resolved_path: "/nm/react/index.mjs".to_string(),
        style: TsRequestStyle::Import,
        package_name: Some("react".to_string()),
        selected_condition: Some("import".to_string()),
        traces: vec![],
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: TsModuleResolutionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

#[test]
fn serde_roundtrip_drift_class_all_variants() {
    for class in [
        TsResolutionDriftClass::NoDrift,
        TsResolutionDriftClass::CandidateOrderMismatch,
        TsResolutionDriftClass::MissingTarget,
        TsResolutionDriftClass::ExtraTarget,
        TsResolutionDriftClass::FullMismatch,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let back: TsResolutionDriftClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, back);
    }
}

#[test]
fn serde_roundtrip_drift_report() {
    let report = classify_resolution_drift(&["x".to_string()], &["x".to_string()]);
    let json = serde_json::to_string(&report).unwrap();
    let back: TsResolutionDriftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn serde_roundtrip_artifact_paths() {
    let paths = TsResolutionArtifactPaths {
        run_manifest: "m.json".to_string(),
        events: "e.jsonl".to_string(),
        commands: "c.txt".to_string(),
        ts_resolution_trace: "t.jsonl".to_string(),
        drift_report: "d.json".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: TsResolutionArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

#[test]
fn serde_roundtrip_run_manifest() {
    let manifest = TsResolutionRunManifest {
        schema_version: "v1".to_string(),
        scenario_id: "s1".to_string(),
        generated_at_utc: "2026-03-08T00:00:00Z".to_string(),
        trace_count: 3,
        drift_class: TsResolutionDriftClass::NoDrift,
        artifact_paths: TsResolutionArtifactPaths {
            run_manifest: "m.json".to_string(),
            events: "e.jsonl".to_string(),
            commands: "c.txt".to_string(),
            ts_resolution_trace: "t.jsonl".to_string(),
            drift_report: "d.json".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TsResolutionRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn serde_roundtrip_resolver_with_files_and_packages() {
    let mut resolver = resolver_with_root("/proj");
    resolver.register_file("/proj/src/index.ts");
    let pkg = TsPackageDefinition::new("lodash", "/proj/nm/lodash")
        .with_export(".", make_export_target(&[("import", "./index.mjs")], None));
    resolver.register_package(pkg);
    let json = serde_json::to_string(&resolver).unwrap();
    let back: DeterministicTsModuleResolver = serde_json::from_str(&json).unwrap();
    assert_eq!(resolver, back);
}

// ===========================================================================
// Section 3: Display / Debug implementations
// ===========================================================================

#[test]
fn error_display_contains_stable_code_and_message() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::EmptySpecifier,
        message: "specifier empty".to_string(),
        traces: vec![],
    };
    let display = format!("{err}");
    assert!(display.contains("FE-TSRES-0001"));
    assert!(display.contains("specifier empty"));
}

#[test]
fn error_display_module_not_found() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::ModuleNotFound,
        message: "could not resolve 'foo'".to_string(),
        traces: vec![],
    };
    let display = format!("{err}");
    assert!(display.contains("FE-TSRES-0005"));
    assert!(display.contains("could not resolve 'foo'"));
}

#[test]
fn error_implements_std_error() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::MissingReferrer,
        message: "no referrer".to_string(),
        traces: vec![],
    };
    // std::error::Error is implemented; verify via trait object coercion.
    let _as_error: &dyn std::error::Error = &err;
}

#[test]
fn debug_format_for_resolution_mode() {
    let debug = format!("{:?}", TsModuleResolutionMode::Bundler);
    assert!(debug.contains("Bundler"));
}

#[test]
fn debug_format_for_request_style() {
    let debug = format!("{:?}", TsRequestStyle::Import);
    assert!(debug.contains("Import"));
}

#[test]
fn debug_format_for_drift_class() {
    let debug = format!("{:?}", TsResolutionDriftClass::CandidateOrderMismatch);
    assert!(debug.contains("CandidateOrderMismatch"));
}

// ===========================================================================
// Section 4: Error code stable_code mapping
// ===========================================================================

#[test]
fn stable_codes_are_unique_and_prefixed() {
    let codes = [
        TsResolutionErrorCode::EmptySpecifier,
        TsResolutionErrorCode::MissingReferrer,
        TsResolutionErrorCode::InvalidReferrer,
        TsResolutionErrorCode::PackageResolutionFailed,
        TsResolutionErrorCode::ModuleNotFound,
    ];
    let mut seen = BTreeSet::new();
    for code in &codes {
        let stable = code.stable_code();
        assert!(stable.starts_with("FE-TSRES-"), "code should have FE-TSRES- prefix");
        assert!(seen.insert(stable), "duplicate stable code: {stable}");
    }
    assert_eq!(seen.len(), 5);
}

// ===========================================================================
// Section 5: Resolver — relative specifier resolution
// ===========================================================================

#[test]
fn resolve_relative_import_ts_extension() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/helper.ts");
    let req = import_req("./helper").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/helper.ts");
    assert_eq!(outcome.style, TsRequestStyle::Import);
}

#[test]
fn resolve_relative_import_tsx_extension() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/App.tsx");
    let req = import_req("./App").with_referrer("/workspace/src/index.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/App.tsx");
}

#[test]
fn resolve_relative_import_mts_extension() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/lib.mts");
    let req = import_req("./lib").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/lib.mts");
}

#[test]
fn resolve_relative_parent_directory() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/utils.ts");
    let req = import_req("../utils").with_referrer("/workspace/src/deep/nested.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/utils.ts");
}

#[test]
fn resolve_relative_index_ts_fallback() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/components/index.ts");
    let req = import_req("./components").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/components/index.ts");
}

#[test]
fn resolve_relative_require_cts_extension() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/config.cts");
    let req = require_req("./config").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/config.cts");
}

#[test]
fn resolve_relative_require_cjs_extension() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/legacy.cjs");
    let req = require_req("./legacy").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/legacy.cjs");
}

// ===========================================================================
// Section 6: Resolver — absolute specifier resolution
// ===========================================================================

#[test]
fn resolve_absolute_specifier_ts() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/global.ts");
    let req = import_req("/workspace/global");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/global.ts");
}

#[test]
fn resolve_absolute_specifier_exact_match() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/exact.js");
    let req = import_req("/workspace/exact.js");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/exact.js");
}

// ===========================================================================
// Section 7: Error handling
// ===========================================================================

#[test]
fn empty_specifier_returns_error() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
}

#[test]
fn whitespace_only_specifier_returns_error() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("   \t  ");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
}

#[test]
fn relative_without_referrer_returns_error() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("./foo");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::MissingReferrer);
}

#[test]
fn parent_relative_without_referrer_returns_error() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("../foo");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::MissingReferrer);
}

#[test]
fn builtin_referrer_returns_invalid() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("./foo").with_referrer("builtin:fs");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn external_referrer_returns_invalid() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("./foo").with_referrer("external:cdn");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn empty_referrer_returns_invalid() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("./foo").with_referrer("");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn module_not_found_when_file_not_registered() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("./nonexistent").with_referrer("/workspace/src/main.ts");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::ModuleNotFound);
}

#[test]
fn error_traces_are_populated_on_failure() {
    let resolver = resolver_with_root("/workspace");
    let req = import_req("");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert!(!err.traces.is_empty());
    assert!(err.traces.iter().any(|t| t.outcome == "deny"));
}

// ===========================================================================
// Section 8: Package exports resolution
// ===========================================================================

#[test]
fn resolve_package_with_import_condition() {
    let mut resolver = resolver_with_root("/workspace");
    let target = make_export_target(
        &[("import", "./dist/esm.mjs"), ("require", "./dist/cjs.cjs")],
        None,
    );
    let pkg = TsPackageDefinition::new("mylib", "/workspace/node_modules/mylib")
        .with_export(".", target);
    resolver.register_package(pkg);
    resolver.register_file("/workspace/node_modules/mylib/dist/esm.mjs");

    let req = import_req("mylib");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/node_modules/mylib/dist/esm.mjs");
    assert_eq!(outcome.package_name.as_deref(), Some("mylib"));
    assert_eq!(outcome.selected_condition.as_deref(), Some("import"));
}

#[test]
fn resolve_package_with_require_condition() {
    let mut resolver = resolver_with_root("/workspace");
    let target = make_export_target(
        &[("import", "./dist/esm.mjs"), ("require", "./dist/cjs.cjs")],
        None,
    );
    let pkg = TsPackageDefinition::new("mylib", "/workspace/node_modules/mylib")
        .with_export(".", target);
    resolver.register_package(pkg);
    resolver.register_file("/workspace/node_modules/mylib/dist/cjs.cjs");

    let req = require_req("mylib");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/node_modules/mylib/dist/cjs.cjs");
    assert_eq!(outcome.selected_condition.as_deref(), Some("require"));
}

#[test]
fn resolve_package_fallback_when_no_conditions_match() {
    let mut resolver = resolver_with_root("/workspace");
    let target = make_export_target(&[], Some("./lib/main.js"));
    let pkg = TsPackageDefinition::new("fallback-lib", "/workspace/nm/fallback-lib")
        .with_export(".", target);
    resolver.register_package(pkg);
    resolver.register_file("/workspace/nm/fallback-lib/lib/main.js");

    let req = import_req("fallback-lib");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/nm/fallback-lib/lib/main.js");
}

#[test]
fn resolve_scoped_package() {
    let mut resolver = resolver_with_root("/workspace");
    let target = make_export_target(&[("import", "./index.mjs")], None);
    let pkg = TsPackageDefinition::new("@org/utils", "/workspace/nm/@org/utils")
        .with_export(".", target);
    resolver.register_package(pkg);
    resolver.register_file("/workspace/nm/@org/utils/index.mjs");

    let req = import_req("@org/utils");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.package_name.as_deref(), Some("@org/utils"));
    assert_eq!(outcome.resolved_path, "/workspace/nm/@org/utils/index.mjs");
}

#[test]
fn resolve_package_subpath_export() {
    let mut resolver = resolver_with_root("/workspace");
    let target = make_export_target(&[("import", "./helpers.mjs")], None);
    let pkg = TsPackageDefinition::new("toolkit", "/workspace/nm/toolkit")
        .with_export("./helpers", target);
    resolver.register_package(pkg);
    resolver.register_file("/workspace/nm/toolkit/helpers.mjs");

    let req = import_req("toolkit/helpers");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/nm/toolkit/helpers.mjs");
}

#[test]
fn package_no_matching_export_entry_returns_error() {
    let mut resolver = resolver_with_root("/workspace");
    let target = make_export_target(&[("import", "./main.mjs")], None);
    let pkg = TsPackageDefinition::new("strict", "/workspace/nm/strict")
        .with_export(".", target);
    resolver.register_package(pkg);

    // Request a subpath that has no export entry
    let req = import_req("strict/nonexistent");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::PackageResolutionFailed);
}

#[test]
fn package_no_matching_condition_and_no_fallback_returns_error() {
    let mut resolver = resolver_with_root("/workspace");
    // Only "types" condition, but resolver checks import conditions in order:
    // import, types, default — so "types" WILL match for an import request.
    // Use a condition that does NOT match anything.
    let target = make_export_target(&[("node", "./dist/node.js")], None);
    let pkg = TsPackageDefinition::new("strict2", "/workspace/nm/strict2")
        .with_export(".", target);
    resolver.register_package(pkg);

    let req = import_req("strict2");
    let err = resolver.resolve(&req, &ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::PackageResolutionFailed);
}

// ===========================================================================
// Section 9: Path mapping / alias resolution
// ===========================================================================

#[test]
fn path_alias_simple_wildcard() {
    let mut paths = BTreeMap::new();
    paths.insert("@utils/*".to_string(), vec!["src/utils/*".to_string()]);
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        paths,
        ..Default::default()
    });
    resolver.register_file("/workspace/src/utils/math.ts");

    let req = import_req("@utils/math");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/utils/math.ts");
}

#[test]
fn path_alias_multiple_replacements_tries_both() {
    let mut paths = BTreeMap::new();
    paths.insert(
        "@lib/*".to_string(),
        vec!["src/lib/*".to_string(), "vendor/lib/*".to_string()],
    );
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        paths,
        ..Default::default()
    });
    // Only the second replacement's file exists
    resolver.register_file("/workspace/vendor/lib/foo.ts");

    let req = import_req("@lib/foo");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/vendor/lib/foo.ts");
}

#[test]
fn path_alias_more_specific_pattern_wins() {
    let mut paths = BTreeMap::new();
    paths.insert("@/*".to_string(), vec!["src/*".to_string()]);
    paths.insert("@/components/*".to_string(), vec!["src/ui/components/*".to_string()]);
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        paths,
        ..Default::default()
    });
    resolver.register_file("/workspace/src/ui/components/Button.ts");

    let req = import_req("@/components/Button");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/ui/components/Button.ts");
}

// ===========================================================================
// Section 10: baseUrl resolution
// ===========================================================================

#[test]
fn base_url_dot_uses_project_root() {
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        base_url: ".".to_string(),
        ..Default::default()
    });
    resolver.register_file("/workspace/utils.ts");

    let req = import_req("utils");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/utils.ts");
}

#[test]
fn base_url_relative_joins_with_root() {
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        base_url: "src".to_string(),
        ..Default::default()
    });
    resolver.register_file("/workspace/src/helpers.ts");

    let req = import_req("helpers");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/helpers.ts");
}

#[test]
fn base_url_absolute_used_directly() {
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        base_url: "/custom/base".to_string(),
        ..Default::default()
    });
    resolver.register_file("/custom/base/lib.ts");

    let req = import_req("lib");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/custom/base/lib.ts");
}

#[test]
fn empty_base_url_defaults_to_dot() {
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        base_url: "   ".to_string(),
        ..Default::default()
    });
    resolver.register_file("/workspace/utils.ts");

    let req = import_req("utils");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/utils.ts");
}

// ===========================================================================
// Section 11: Extension resolution order
// ===========================================================================

#[test]
fn import_probes_ts_before_js() {
    let mut resolver = resolver_with_root("/workspace");
    // Register both .ts and .js — .ts should win because it comes first in probe order
    resolver.register_file("/workspace/src/mod.ts");
    resolver.register_file("/workspace/src/mod.js");
    let req = import_req("./mod").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/mod.ts");
}

#[test]
fn require_probes_cts_before_ts() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/lib.cts");
    resolver.register_file("/workspace/src/lib.ts");
    let req = require_req("./lib").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/lib.cts");
}

#[test]
fn exact_path_match_tried_first_before_extensions() {
    let mut resolver = resolver_with_root("/workspace");
    // If the specifier matches an exact registered file (with extension), it resolves directly.
    resolver.register_file("/workspace/src/exact.js");
    resolver.register_file("/workspace/src/exact.js.ts"); // unlikely but tests priority
    let req = import_req("./exact.js").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/exact.js");
}

// ===========================================================================
// Section 12: Deterministic behavior
// ===========================================================================

#[test]
fn resolver_is_deterministic_across_repeated_resolves() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/a.ts");
    resolver.register_file("/workspace/src/a.tsx");
    let req = import_req("./a").with_referrer("/workspace/src/main.ts");

    let results: Vec<_> = (0..10)
        .map(|_| resolver.resolve(&req, &ctx()).unwrap().resolved_path.clone())
        .collect();

    // All results must be identical
    let first = &results[0];
    for result in &results {
        assert_eq!(result, first);
    }
}

#[test]
fn resolver_deterministic_with_multiple_path_aliases() {
    let mut paths = BTreeMap::new();
    paths.insert("@/*".to_string(), vec!["src/*".to_string()]);
    paths.insert("@utils/*".to_string(), vec!["src/utils/*".to_string()]);
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        paths,
        ..Default::default()
    });
    resolver.register_file("/workspace/src/utils/math.ts");

    let req = import_req("@utils/math");
    let results: Vec<_> = (0..5)
        .map(|_| resolver.resolve(&req, &ctx()).unwrap().resolved_path.clone())
        .collect();
    let first = &results[0];
    for r in &results {
        assert_eq!(r, first);
    }
}

#[test]
fn file_registration_order_does_not_affect_resolution() {
    // Register files in different orders and confirm same resolution
    let build_resolver = |files: &[&str]| {
        let mut resolver = resolver_with_root("/workspace");
        for f in files {
            resolver.register_file(*f);
        }
        resolver
    };

    let files_a = ["/workspace/src/mod.ts", "/workspace/src/mod.tsx"];
    let files_b = ["/workspace/src/mod.tsx", "/workspace/src/mod.ts"];

    let resolver_a = build_resolver(&files_a);
    let resolver_b = build_resolver(&files_b);

    let req = import_req("./mod").with_referrer("/workspace/src/main.ts");
    let outcome_a = resolver_a.resolve(&req, &ctx()).unwrap();
    let outcome_b = resolver_b.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome_a.resolved_path, outcome_b.resolved_path);
}

// ===========================================================================
// Section 13: Trace event verification
// ===========================================================================

#[test]
fn successful_resolution_traces_have_correct_ids() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/found.ts");
    let req = import_req("./found").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    for trace in &outcome.traces {
        assert_eq!(trace.trace_id, "trace-int");
        assert_eq!(trace.decision_id, "decision-int");
        assert_eq!(trace.policy_id, "policy-int");
        assert_eq!(trace.component, "ts_module_resolver");
    }
}

#[test]
fn probe_sequence_contains_resolved_path() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/a.tsx");
    let req = import_req("./a").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    let probes = outcome.probe_sequence();
    assert!(probes.contains(&"/workspace/src/a.tsx".to_string()));
}

#[test]
fn probe_sequence_empty_for_outcome_with_no_extension_probe_events() {
    let outcome = TsModuleResolutionOutcome {
        request_specifier: "test".to_string(),
        resolved_path: "/a.ts".to_string(),
        style: TsRequestStyle::Import,
        package_name: None,
        selected_condition: None,
        traces: vec![],
    };
    assert!(outcome.probe_sequence().is_empty());
}

// ===========================================================================
// Section 14: Drift detection
// ===========================================================================

#[test]
fn drift_no_drift_identical_lists() {
    let report = classify_resolution_drift(
        &["a".to_string(), "b".to_string()],
        &["a".to_string(), "b".to_string()],
    );
    assert!(!report.drift_detected);
    assert_eq!(report.class, TsResolutionDriftClass::NoDrift);
}

#[test]
fn drift_candidate_order_mismatch_same_elements() {
    let report = classify_resolution_drift(
        &["x".to_string(), "y".to_string()],
        &["y".to_string(), "x".to_string()],
    );
    assert!(report.drift_detected);
    assert_eq!(report.class, TsResolutionDriftClass::CandidateOrderMismatch);
}

#[test]
fn drift_missing_target_subset() {
    let report = classify_resolution_drift(
        &["a".to_string(), "b".to_string(), "c".to_string()],
        &["a".to_string()],
    );
    assert!(report.drift_detected);
    assert_eq!(report.class, TsResolutionDriftClass::MissingTarget);
}

#[test]
fn drift_extra_target_superset() {
    let report = classify_resolution_drift(
        &["a".to_string()],
        &["a".to_string(), "b".to_string()],
    );
    assert!(report.drift_detected);
    assert_eq!(report.class, TsResolutionDriftClass::ExtraTarget);
}

#[test]
fn drift_full_mismatch_disjoint() {
    let report = classify_resolution_drift(
        &["alpha".to_string()],
        &["beta".to_string()],
    );
    assert!(report.drift_detected);
    assert_eq!(report.class, TsResolutionDriftClass::FullMismatch);
}

#[test]
fn drift_both_empty_is_no_drift() {
    let report = classify_resolution_drift(&[], &[]);
    assert!(!report.drift_detected);
    assert_eq!(report.class, TsResolutionDriftClass::NoDrift);
}

#[test]
fn drift_remediation_messages_nonempty_for_all_classes() {
    let tests: &[(&[&str], &[&str])] = &[
        (&["a"], &["a"]),         // NoDrift
        (&["a", "b"], &["b", "a"]), // OrderMismatch
        (&["a", "b"], &["a"]),    // MissingTarget
        (&["a"], &["a", "b"]),    // ExtraTarget
        (&["a"], &["b"]),         // FullMismatch
    ];
    for (reference, observed) in tests {
        let ref_vec: Vec<String> = reference.iter().map(|s| s.to_string()).collect();
        let obs_vec: Vec<String> = observed.iter().map(|s| s.to_string()).collect();
        let report = classify_resolution_drift(&ref_vec, &obs_vec);
        assert!(!report.remediation.is_empty(), "remediation should be non-empty");
    }
}

#[test]
fn drift_report_preserves_input_vectors() {
    let reference = vec!["r1".to_string(), "r2".to_string()];
    let observed = vec!["o1".to_string()];
    let report = classify_resolution_drift(&reference, &observed);
    assert_eq!(report.reference_candidates, reference);
    assert_eq!(report.observed_candidates, observed);
}

// ===========================================================================
// Section 15: Artifact writing
// ===========================================================================

#[test]
fn write_artifacts_creates_all_files() {
    let dir = unique_temp_dir("write_all");
    let _ = fs::remove_dir_all(&dir);
    let drift = classify_resolution_drift(&["a".to_string()], &["a".to_string()]);
    let trace = TsResolutionTraceEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "test".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: "none".to_string(),
        detail: "detail".to_string(),
        candidate: Some("/a.ts".to_string()),
    };
    let manifest = write_ts_resolution_artifacts(
        &dir,
        "scenario-integ",
        "2026-03-08T12:00:00Z",
        &["cmd1".to_string(), "cmd2".to_string()],
        &[trace],
        &drift,
    )
    .unwrap();
    assert!(dir.join("run_manifest.json").exists());
    assert!(dir.join("events.jsonl").exists());
    assert!(dir.join("commands.txt").exists());
    assert!(dir.join("ts_resolution_trace.jsonl").exists());
    assert!(dir.join("drift_report.json").exists());
    assert_eq!(manifest.trace_count, 1);
    assert_eq!(manifest.scenario_id, "scenario-integ");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_artifacts_manifest_schema_version() {
    let dir = unique_temp_dir("schema_ver");
    let _ = fs::remove_dir_all(&dir);
    let drift = classify_resolution_drift(&[], &[]);
    let manifest = write_ts_resolution_artifacts(
        &dir,
        "sv-test",
        "2026-01-01T00:00:00Z",
        &[],
        &[],
        &drift,
    )
    .unwrap();
    assert_eq!(manifest.schema_version, "rgc.ts-module-resolution.parity.v1");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_artifacts_commands_file_content() {
    let dir = unique_temp_dir("cmds");
    let _ = fs::remove_dir_all(&dir);
    let drift = classify_resolution_drift(&[], &[]);
    write_ts_resolution_artifacts(
        &dir,
        "cmd-test",
        "2026-01-01T00:00:00Z",
        &["alpha".to_string(), "bravo".to_string()],
        &[],
        &drift,
    )
    .unwrap();
    let content = fs::read_to_string(dir.join("commands.txt")).unwrap();
    assert!(content.contains("alpha"));
    assert!(content.contains("bravo"));
    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// Section 16: Project root normalization
// ===========================================================================

#[test]
fn resolver_normalizes_project_root_with_dotdot() {
    let resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/a/b/../c".to_string(),
        ..Default::default()
    });
    let json = serde_json::to_string(&resolver).unwrap();
    assert!(json.contains("/a/c"));
    assert!(!json.contains(".."));
}

#[test]
fn resolver_normalizes_project_root_with_dot() {
    let resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/a/./b".to_string(),
        ..Default::default()
    });
    let json = serde_json::to_string(&resolver).unwrap();
    assert!(json.contains("/a/b"));
}

#[test]
fn register_file_relative_path_joined_with_root() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("src/index.ts");
    let req = import_req("./src/index").with_referrer("/workspace/package.json");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert!(outcome.resolved_path.starts_with("/workspace/"));
}

// ===========================================================================
// Section 17: Package definition builder
// ===========================================================================

#[test]
fn package_definition_new_has_empty_exports() {
    let pkg = TsPackageDefinition::new("test-pkg", "/nm/test-pkg");
    assert!(pkg.exports.is_empty());
    assert_eq!(pkg.package_name, "test-pkg");
}

#[test]
fn package_definition_with_export_chaining() {
    let pkg = TsPackageDefinition::new("multi", "/nm/multi")
        .with_export(".", make_export_target(&[("import", "./a.mjs")], None))
        .with_export("./sub", make_export_target(&[("import", "./b.mjs")], None));
    assert_eq!(pkg.exports.len(), 2);
    assert!(pkg.exports.contains_key("."));
    assert!(pkg.exports.contains_key("./sub"));
}

#[test]
fn package_export_target_default_is_empty() {
    let target = TsPackageExportTarget::default();
    assert!(target.condition_targets.is_empty());
    assert!(target.fallback_target.is_none());
}

// ===========================================================================
// Section 18: Edge cases and miscellaneous
// ===========================================================================

#[test]
fn bare_specifier_without_package_falls_through_to_base_url() {
    let mut resolver = resolver_with_root("/workspace");
    // No package registered for "utils", so it falls through to baseUrl resolution
    resolver.register_file("/workspace/utils.ts");
    let req = import_req("utils");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/utils.ts");
    assert!(outcome.package_name.is_none());
}

#[test]
fn deeply_nested_relative_resolution() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/a/b/c/d.ts");
    let req = import_req("./a/b/c/d").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/a/b/c/d.ts");
}

#[test]
fn multiple_parent_traversals_in_specifier() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/shared/util.ts");
    let req = import_req("../../shared/util")
        .with_referrer("/workspace/src/deep/nested/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/shared/util.ts");
}

#[test]
fn resolution_outcome_request_specifier_matches_input() {
    let mut resolver = resolver_with_root("/workspace");
    resolver.register_file("/workspace/src/foo.ts");
    let req = import_req("./foo").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(outcome.request_specifier, "./foo");
}

#[test]
fn scoped_package_with_deep_subpath() {
    let mut resolver = resolver_with_root("/workspace");
    let target = make_export_target(&[("import", "./dist/components/Button.mjs")], None);
    let pkg = TsPackageDefinition::new("@ui/kit", "/workspace/nm/@ui/kit")
        .with_export("./components/Button", target);
    resolver.register_package(pkg);
    resolver.register_file("/workspace/nm/@ui/kit/dist/components/Button.mjs");

    let req = import_req("@ui/kit/components/Button");
    let outcome = resolver.resolve(&req, &ctx()).unwrap();
    assert_eq!(
        outcome.resolved_path,
        "/workspace/nm/@ui/kit/dist/components/Button.mjs",
    );
    assert_eq!(outcome.package_name.as_deref(), Some("@ui/kit"));
}
