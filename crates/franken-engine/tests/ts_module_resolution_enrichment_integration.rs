#![forbid(unsafe_code)]
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

use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ts_module_resolution::{
    DeterministicTsModuleResolver, TsExportMapHashCatalog, TsExportMapHashCatalogPackage,
    TsIndexFallbackPackage, TsIndexedExportEntry, TsIndexedSubpathEntry, TsModuleArtIndexReport,
    TsModuleIndexIdentityReport, TsModuleRequest, TsModuleResolutionConfig,
    TsModuleResolutionError, TsModuleResolutionIndexBundle, TsModuleResolutionMode,
    TsModuleResolutionOutcome, TsPackageArtEdge, TsPackageArtNode, TsPackageArtTerminal,
    TsPackageDefinition, TsPackageExportTarget, TsPerfectHashLayout, TsPerfectHashSlot,
    TsRequestStyle, TsResolutionArtifactPaths, TsResolutionContext, TsResolutionDriftClass,
    TsResolutionDriftReport, TsResolutionErrorCode, TsResolutionIndexArtifactPaths,
    TsResolutionIndexBuildPolicy, TsResolutionIndexFallbackReason, TsResolutionIndexRunManifest,
    TsResolutionIndexStepLog, TsResolutionIndexTraceIds, TsResolutionIndexValidationReport,
    TsResolutionRunManifest, TsResolutionTraceEvent, TsWildcardExportEntry,
    classify_resolution_drift, write_ts_resolution_artifacts, write_ts_resolution_index_artifacts,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn enrichment_ctx() -> TsResolutionContext {
    TsResolutionContext::new("trace-enr", "decision-enr", "policy-enr")
}

fn enrichment_resolver() -> DeterministicTsModuleResolver {
    DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/workspace".to_string(),
        ..Default::default()
    })
}

fn enrichment_import(specifier: &str) -> TsModuleRequest {
    TsModuleRequest::new(specifier, TsRequestStyle::Import)
}

fn enrichment_require(specifier: &str) -> TsModuleRequest {
    TsModuleRequest::new(specifier, TsRequestStyle::Require)
}

fn make_target(conditions: &[(&str, &str)], fallback: Option<&str>) -> TsPackageExportTarget {
    let mut condition_targets = BTreeMap::new();
    for (k, v) in conditions {
        condition_targets.insert(k.to_string(), v.to_string());
    }
    TsPackageExportTarget {
        condition_targets,
        fallback_target: fallback.map(|s| s.to_string()),
    }
}

fn unique_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frx_tsres_enr_{label}_{}_{}",
        std::process::id(),
        nanos,
    ))
}

const FIXED_POINT_ONE: u64 = 1_000_000;

// ===========================================================================
// Section 1: TsModuleResolutionMode enum exhaustive coverage
// ===========================================================================

#[test]
fn enrichment_resolution_mode_node16_serde() {
    let mode = TsModuleResolutionMode::Node16;
    let json = serde_json::to_string(&mode).unwrap();
    assert_eq!(json, "\"node16\"");
    let back: TsModuleResolutionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn enrichment_resolution_mode_node_next_serde() {
    let mode = TsModuleResolutionMode::NodeNext;
    let json = serde_json::to_string(&mode).unwrap();
    assert_eq!(json, "\"node_next\"");
    let back: TsModuleResolutionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn enrichment_resolution_mode_bundler_serde() {
    let mode = TsModuleResolutionMode::Bundler;
    let json = serde_json::to_string(&mode).unwrap();
    assert_eq!(json, "\"bundler\"");
    let back: TsModuleResolutionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn enrichment_resolution_mode_default_variant() {
    let mode = TsModuleResolutionMode::default();
    assert_eq!(mode, TsModuleResolutionMode::NodeNext);
}

#[test]
fn enrichment_resolution_mode_clone_eq() {
    let a = TsModuleResolutionMode::Bundler;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_resolution_mode_debug() {
    let dbg = format!("{:?}", TsModuleResolutionMode::Node16);
    assert!(dbg.contains("Node16"));
}

// ===========================================================================
// Section 2: TsRequestStyle enum
// ===========================================================================

#[test]
fn enrichment_request_style_import_serde() {
    let style = TsRequestStyle::Import;
    let json = serde_json::to_string(&style).unwrap();
    assert_eq!(json, "\"import\"");
    let back: TsRequestStyle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, style);
}

#[test]
fn enrichment_request_style_require_serde() {
    let style = TsRequestStyle::Require;
    let json = serde_json::to_string(&style).unwrap();
    assert_eq!(json, "\"require\"");
    let back: TsRequestStyle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, style);
}

#[test]
fn enrichment_request_style_clone_copy() {
    let a = TsRequestStyle::Import;
    let b = a;
    let c = a.clone();
    assert_eq!(b, c);
}

// ===========================================================================
// Section 3: TsResolutionContext
// ===========================================================================

#[test]
fn enrichment_context_new_from_string_refs() {
    let ctx = TsResolutionContext::new("t1", "d1", "p1");
    assert_eq!(ctx.trace_id, "t1");
    assert_eq!(ctx.decision_id, "d1");
    assert_eq!(ctx.policy_id, "p1");
}

#[test]
fn enrichment_context_new_from_owned_strings() {
    let ctx = TsResolutionContext::new(
        String::from("trace"),
        String::from("dec"),
        String::from("pol"),
    );
    assert_eq!(ctx.trace_id, "trace");
}

#[test]
fn enrichment_context_serde_roundtrip() {
    let ctx = enrichment_ctx();
    let json = serde_json::to_string(&ctx).unwrap();
    let back: TsResolutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

#[test]
fn enrichment_context_clone_eq() {
    let a = enrichment_ctx();
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// Section 4: TsModuleRequest builder
// ===========================================================================

#[test]
fn enrichment_request_new_import() {
    let req = TsModuleRequest::new("./util", TsRequestStyle::Import);
    assert_eq!(req.specifier, "./util");
    assert!(req.referrer.is_none());
    assert_eq!(req.style, TsRequestStyle::Import);
}

#[test]
fn enrichment_request_new_require() {
    let req = TsModuleRequest::new("lodash", TsRequestStyle::Require);
    assert_eq!(req.specifier, "lodash");
    assert_eq!(req.style, TsRequestStyle::Require);
}

#[test]
fn enrichment_request_with_referrer_chain() {
    let req = TsModuleRequest::new("./a", TsRequestStyle::Import).with_referrer("/src/main.ts");
    assert_eq!(req.referrer.as_deref(), Some("/src/main.ts"));
}

#[test]
fn enrichment_request_serde_roundtrip() {
    let req = enrichment_import("react").with_referrer("/index.ts");
    let json = serde_json::to_string(&req).unwrap();
    let back: TsModuleRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn enrichment_request_without_referrer_serde() {
    let req = enrichment_import("react");
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"referrer\":null"));
}

// ===========================================================================
// Section 5: TsModuleResolutionConfig defaults and serde
// ===========================================================================

#[test]
fn enrichment_config_default_mode_is_node_next() {
    let cfg = TsModuleResolutionConfig::default();
    assert_eq!(cfg.mode, TsModuleResolutionMode::NodeNext);
}

#[test]
fn enrichment_config_default_base_url() {
    let cfg = TsModuleResolutionConfig::default();
    assert_eq!(cfg.base_url, ".");
}

#[test]
fn enrichment_config_default_paths_empty() {
    let cfg = TsModuleResolutionConfig::default();
    assert!(cfg.paths.is_empty());
}

#[test]
fn enrichment_config_import_extensions_include_ts_tsx_mts() {
    let cfg = TsModuleResolutionConfig::default();
    assert!(cfg.import_extensions.contains(&".ts".to_string()));
    assert!(cfg.import_extensions.contains(&".tsx".to_string()));
    assert!(cfg.import_extensions.contains(&".mts".to_string()));
}

#[test]
fn enrichment_config_require_extensions_include_cts_cjs() {
    let cfg = TsModuleResolutionConfig::default();
    assert!(cfg.require_extensions.contains(&".cts".to_string()));
    assert!(cfg.require_extensions.contains(&".cjs".to_string()));
}

#[test]
fn enrichment_config_import_conditions_order() {
    let cfg = TsModuleResolutionConfig::default();
    assert_eq!(cfg.import_conditions[0], "import");
    assert_eq!(cfg.import_conditions[1], "types");
    assert_eq!(cfg.import_conditions[2], "default");
}

#[test]
fn enrichment_config_require_conditions_order() {
    let cfg = TsModuleResolutionConfig::default();
    assert_eq!(cfg.require_conditions[0], "require");
    assert_eq!(cfg.require_conditions[1], "default");
}

#[test]
fn enrichment_config_serde_roundtrip_custom() {
    let mut paths = BTreeMap::new();
    paths.insert("@utils/*".to_string(), vec!["src/utils/*".to_string()]);
    let cfg = TsModuleResolutionConfig {
        project_root: "/app".to_string(),
        base_url: "src".to_string(),
        mode: TsModuleResolutionMode::Bundler,
        paths,
        import_conditions: vec!["import".to_string()],
        require_conditions: vec!["require".to_string()],
        import_extensions: vec![".ts".to_string()],
        require_extensions: vec![".cts".to_string()],
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: TsModuleResolutionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_config_index_extensions_include_index_ts() {
    let cfg = TsModuleResolutionConfig::default();
    assert!(cfg.import_extensions.contains(&"/index.ts".to_string()));
    assert!(cfg.require_extensions.contains(&"/index.ts".to_string()));
}

// ===========================================================================
// Section 6: TsPackageExportTarget
// ===========================================================================

#[test]
fn enrichment_export_target_default_empty() {
    let target = TsPackageExportTarget::default();
    assert!(target.condition_targets.is_empty());
    assert!(target.fallback_target.is_none());
}

#[test]
fn enrichment_export_target_serde_roundtrip() {
    let target = make_target(&[("import", "./dist/index.mjs")], Some("./lib/main.js"));
    let json = serde_json::to_string(&target).unwrap();
    let back: TsPackageExportTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(target, back);
}

#[test]
fn enrichment_export_target_multiple_conditions() {
    let target = make_target(
        &[
            ("import", "./esm.mjs"),
            ("require", "./cjs.cjs"),
            ("types", "./types.d.ts"),
        ],
        None,
    );
    assert_eq!(target.condition_targets.len(), 3);
}

#[test]
fn enrichment_export_target_with_only_fallback() {
    let target = make_target(&[], Some("./fallback.js"));
    assert!(target.condition_targets.is_empty());
    assert_eq!(target.fallback_target.as_deref(), Some("./fallback.js"));
}

// ===========================================================================
// Section 7: TsPackageDefinition builder
// ===========================================================================

#[test]
fn enrichment_package_definition_new() {
    let pkg = TsPackageDefinition::new("react", "/nm/react");
    assert_eq!(pkg.package_name, "react");
    assert_eq!(pkg.package_root, "/nm/react");
    assert!(pkg.exports.is_empty());
}

#[test]
fn enrichment_package_definition_with_export_chaining() {
    let pkg = TsPackageDefinition::new("pkg", "/nm/pkg")
        .with_export(".", make_target(&[("import", "./index.mjs")], None))
        .with_export("./utils", make_target(&[("import", "./utils.mjs")], None));
    assert_eq!(pkg.exports.len(), 2);
    assert!(pkg.exports.contains_key("."));
    assert!(pkg.exports.contains_key("./utils"));
}

#[test]
fn enrichment_package_definition_serde_roundtrip() {
    let pkg = TsPackageDefinition::new("@scope/lib", "/nm/@scope/lib").with_export(
        ".",
        make_target(&[("import", "./index.mjs")], Some("./main.js")),
    );
    let json = serde_json::to_string(&pkg).unwrap();
    let back: TsPackageDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, back);
}

#[test]
fn enrichment_package_definition_overwrite_export() {
    let target_a = make_target(&[("import", "./a.mjs")], None);
    let target_b = make_target(&[("import", "./b.mjs")], None);
    let pkg = TsPackageDefinition::new("pkg", "/nm/pkg")
        .with_export(".", target_a)
        .with_export(".", target_b.clone());
    assert_eq!(pkg.exports["."], target_b);
}

// ===========================================================================
// Section 8: TsResolutionErrorCode stable codes exhaustive
// ===========================================================================

#[test]
fn enrichment_error_code_empty_specifier() {
    assert_eq!(
        TsResolutionErrorCode::EmptySpecifier.stable_code(),
        "FE-TSRES-0001"
    );
}

#[test]
fn enrichment_error_code_missing_referrer() {
    assert_eq!(
        TsResolutionErrorCode::MissingReferrer.stable_code(),
        "FE-TSRES-0002"
    );
}

#[test]
fn enrichment_error_code_invalid_referrer() {
    assert_eq!(
        TsResolutionErrorCode::InvalidReferrer.stable_code(),
        "FE-TSRES-0003"
    );
}

#[test]
fn enrichment_error_code_package_resolution_failed() {
    assert_eq!(
        TsResolutionErrorCode::PackageResolutionFailed.stable_code(),
        "FE-TSRES-0004"
    );
}

#[test]
fn enrichment_error_code_module_not_found() {
    assert_eq!(
        TsResolutionErrorCode::ModuleNotFound.stable_code(),
        "FE-TSRES-0005"
    );
}

#[test]
fn enrichment_error_code_serde_roundtrip_all_variants() {
    let variants = [
        TsResolutionErrorCode::EmptySpecifier,
        TsResolutionErrorCode::MissingReferrer,
        TsResolutionErrorCode::InvalidReferrer,
        TsResolutionErrorCode::PackageResolutionFailed,
        TsResolutionErrorCode::ModuleNotFound,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let back: TsResolutionErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

// ===========================================================================
// Section 9: TsModuleResolutionError Display and serde
// ===========================================================================

#[test]
fn enrichment_error_display_contains_stable_code() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::ModuleNotFound,
        message: "cannot find module".to_string(),
        traces: vec![],
    };
    let display = format!("{}", err);
    assert!(display.contains("FE-TSRES-0005"));
    assert!(display.contains("cannot find module"));
}

#[test]
fn enrichment_error_display_empty_specifier() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::EmptySpecifier,
        message: "empty".to_string(),
        traces: vec![],
    };
    let display = format!("{}", err);
    assert!(display.starts_with("FE-TSRES-0001"));
}

#[test]
fn enrichment_error_serde_roundtrip_with_traces() {
    let trace = TsResolutionTraceEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "deny".to_string(),
        error_code: "FE-TSRES-0001".to_string(),
        detail: "det".to_string(),
        candidate: None,
    };
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::EmptySpecifier,
        message: "test".to_string(),
        traces: vec![trace],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TsModuleResolutionError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_error_is_std_error() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::EmptySpecifier,
        message: "m".to_string(),
        traces: vec![],
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

// ===========================================================================
// Section 10: TsResolutionTraceEvent
// ===========================================================================

#[test]
fn enrichment_trace_event_serde_roundtrip_with_candidate() {
    let event = TsResolutionTraceEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "ts_module_resolver".to_string(),
        event: "extension_probe".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
        detail: "resolved".to_string(),
        candidate: Some("/a/b.ts".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: TsResolutionTraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_trace_event_serde_roundtrip_without_candidate() {
    let event = TsResolutionTraceEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "deny".to_string(),
        error_code: "FE-TSRES-0001".to_string(),
        detail: "detail".to_string(),
        candidate: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"candidate\":null"));
}

// ===========================================================================
// Section 11: TsModuleResolutionOutcome and probe_sequence
// ===========================================================================

#[test]
fn enrichment_outcome_probe_sequence_filters_extension_probes() {
    let outcome = TsModuleResolutionOutcome {
        request_specifier: "react".to_string(),
        resolved_path: "/nm/react/index.mjs".to_string(),
        style: TsRequestStyle::Import,
        package_name: Some("react".to_string()),
        selected_condition: Some("import".to_string()),
        traces: vec![
            TsResolutionTraceEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "extension_probe".to_string(),
                outcome: "miss".to_string(),
                error_code: "none".to_string(),
                detail: "miss".to_string(),
                candidate: Some("/nm/react/index.ts".to_string()),
            },
            TsResolutionTraceEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "extension_probe".to_string(),
                outcome: "allow".to_string(),
                error_code: "none".to_string(),
                detail: "found".to_string(),
                candidate: Some("/nm/react/index.mjs".to_string()),
            },
            TsResolutionTraceEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "validate_specifier".to_string(),
                outcome: "allow".to_string(),
                error_code: "none".to_string(),
                detail: "ok".to_string(),
                candidate: None,
            },
        ],
    };
    let probes = outcome.probe_sequence();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0], "/nm/react/index.ts");
    assert_eq!(probes[1], "/nm/react/index.mjs");
}

#[test]
fn enrichment_outcome_probe_sequence_empty_when_no_probes() {
    let outcome = TsModuleResolutionOutcome {
        request_specifier: "x".to_string(),
        resolved_path: "/x.ts".to_string(),
        style: TsRequestStyle::Import,
        package_name: None,
        selected_condition: None,
        traces: vec![],
    };
    assert!(outcome.probe_sequence().is_empty());
}

#[test]
fn enrichment_outcome_serde_roundtrip() {
    let outcome = TsModuleResolutionOutcome {
        request_specifier: "./a".to_string(),
        resolved_path: "/ws/a.ts".to_string(),
        style: TsRequestStyle::Require,
        package_name: None,
        selected_condition: None,
        traces: vec![],
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: TsModuleResolutionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

// ===========================================================================
// Section 12: DeterministicTsModuleResolver construction
// ===========================================================================

#[test]
fn enrichment_resolver_normalizes_project_root() {
    let resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/a/b/../c/./d".to_string(),
        ..Default::default()
    });
    let json = serde_json::to_string(&resolver).unwrap();
    assert!(json.contains("/a/c/d"));
    assert!(!json.contains(".."));
}

#[test]
fn enrichment_resolver_empty_base_url_becomes_dot() {
    let resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/ws".to_string(),
        base_url: "   ".to_string(),
        ..Default::default()
    });
    let json = serde_json::to_string(&resolver).unwrap();
    assert!(json.contains("\".\""));
}

#[test]
fn enrichment_resolver_serde_roundtrip() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("src/a.ts");
    resolver.register_file("/workspace/src/b.ts");
    let json = serde_json::to_string(&resolver).unwrap();
    let back: DeterministicTsModuleResolver = serde_json::from_str(&json).unwrap();
    assert_eq!(resolver, back);
}

// ===========================================================================
// Section 13: resolve() — relative specifier paths
// ===========================================================================

#[test]
fn enrichment_resolve_relative_dot_slash() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/helper.ts");
    let req = enrichment_import("./helper").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/helper.ts");
}

#[test]
fn enrichment_resolve_relative_dot_dot_slash() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/utils.ts");
    let req = enrichment_import("../utils").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/utils.ts");
}

#[test]
fn enrichment_resolve_relative_multi_level_parent() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/root.ts");
    let req = enrichment_import("../../root").with_referrer("/workspace/a/b/c.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/root.ts");
}

#[test]
fn enrichment_resolve_relative_tsx() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/App.tsx");
    let req = enrichment_import("./App").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/App.tsx");
}

#[test]
fn enrichment_resolve_relative_mts() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/lib.mts");
    let req = enrichment_import("./lib").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/lib.mts");
}

#[test]
fn enrichment_resolve_relative_index_tsx() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/components/index.tsx");
    let req = enrichment_import("./components").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/components/index.tsx");
}

// ===========================================================================
// Section 14: resolve() — absolute specifier paths
// ===========================================================================

#[test]
fn enrichment_resolve_absolute_specifier() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/abs.ts");
    let req = enrichment_import("/workspace/abs");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/abs.ts");
}

#[test]
fn enrichment_resolve_absolute_with_dots() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/real.ts");
    let req = enrichment_import("/workspace/src/../src/real");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/real.ts");
}

// ===========================================================================
// Section 15: resolve() — bare specifier (baseUrl fallback)
// ===========================================================================

#[test]
fn enrichment_resolve_bare_specifier_base_url_fallback() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/utils.ts");
    let req = enrichment_import("utils");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/utils.ts");
}

#[test]
fn enrichment_resolve_bare_with_custom_base_url() {
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/project".to_string(),
        base_url: "src".to_string(),
        ..Default::default()
    });
    resolver.register_file("/project/src/models/user.ts");
    let req = enrichment_import("models/user");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/project/src/models/user.ts");
}

// ===========================================================================
// Section 16: resolve() — error paths
// ===========================================================================

#[test]
fn enrichment_resolve_empty_specifier_error() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
    assert!(!err.traces.is_empty());
}

#[test]
fn enrichment_resolve_whitespace_only_specifier_error() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("   \t  ");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
}

#[test]
fn enrichment_resolve_relative_no_referrer_error() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("./foo");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::MissingReferrer);
}

#[test]
fn enrichment_resolve_relative_empty_referrer_error() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("./foo").with_referrer("");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn enrichment_resolve_relative_builtin_referrer_error() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("./foo").with_referrer("builtin:node:fs");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn enrichment_resolve_relative_external_referrer_error() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("./foo").with_referrer("external:cdn");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn enrichment_resolve_module_not_found_error() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("./nonexist").with_referrer("/workspace/a.ts");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::ModuleNotFound);
    assert!(err.message.contains("nonexist"));
}

#[test]
fn enrichment_resolve_package_no_export_entry_error() {
    let mut resolver = enrichment_resolver();
    let pkg = TsPackageDefinition::new("strict", "/workspace/nm/strict")
        .with_export(".", make_target(&[("import", "./index.mjs")], None));
    resolver.register_package(pkg);
    let req = enrichment_import("strict/missing-subpath");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::PackageResolutionFailed);
}

#[test]
fn enrichment_resolve_package_no_matching_condition_error() {
    let mut resolver = enrichment_resolver();
    let target = make_target(&[], None);
    let pkg =
        TsPackageDefinition::new("empty-cond", "/workspace/nm/empty-cond").with_export(".", target);
    resolver.register_package(pkg);
    let req = enrichment_import("empty-cond");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::PackageResolutionFailed);
}

// ===========================================================================
// Section 17: resolve() — package exports
// ===========================================================================

#[test]
fn enrichment_resolve_package_import_condition() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/dist/index.mjs");
    let pkg = TsPackageDefinition::new("react", "/workspace/nm/react").with_export(
        ".",
        make_target(
            &[
                ("import", "./dist/index.mjs"),
                ("require", "./dist/index.cjs"),
            ],
            None,
        ),
    );
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(&enrichment_import("react"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/nm/react/dist/index.mjs");
    assert_eq!(outcome.package_name.as_deref(), Some("react"));
    assert_eq!(outcome.selected_condition.as_deref(), Some("import"));
}

#[test]
fn enrichment_resolve_package_require_condition() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/lodash/dist/index.cjs");
    let pkg = TsPackageDefinition::new("lodash", "/workspace/nm/lodash").with_export(
        ".",
        make_target(
            &[
                ("import", "./dist/index.mjs"),
                ("require", "./dist/index.cjs"),
            ],
            None,
        ),
    );
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(&enrichment_require("lodash"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/nm/lodash/dist/index.cjs");
    assert_eq!(outcome.selected_condition.as_deref(), Some("require"));
}

#[test]
fn enrichment_resolve_package_fallback_target() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/fb/main.js");
    let pkg = TsPackageDefinition::new("fb", "/workspace/nm/fb")
        .with_export(".", make_target(&[], Some("./main.js")));
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(&enrichment_import("fb"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/nm/fb/main.js");
    assert_eq!(outcome.selected_condition.as_deref(), Some("fallback"));
}

#[test]
fn enrichment_resolve_scoped_package() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/@org/lib/index.mjs");
    let pkg = TsPackageDefinition::new("@org/lib", "/workspace/nm/@org/lib")
        .with_export(".", make_target(&[("import", "./index.mjs")], None));
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(&enrichment_import("@org/lib"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.package_name.as_deref(), Some("@org/lib"));
}

#[test]
fn enrichment_resolve_package_subpath_export() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/toolkit/utils.mjs");
    let pkg = TsPackageDefinition::new("toolkit", "/workspace/nm/toolkit")
        .with_export("./utils", make_target(&[("import", "./utils.mjs")], None));
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(&enrichment_import("toolkit/utils"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/nm/toolkit/utils.mjs");
}

#[test]
fn enrichment_resolve_package_wildcard_export() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/wc/dist/foo.mjs");
    let target = make_target(&[("import", "./dist/*.mjs")], None);
    let pkg = TsPackageDefinition::new("wc", "/workspace/nm/wc").with_export("./*", target);
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(&enrichment_import("wc/foo"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/nm/wc/dist/foo.mjs");
}

#[test]
fn enrichment_resolve_package_condition_priority_order() {
    // import_conditions: ["import", "types", "default"]
    // If both "import" and "types" exist, "import" wins because it's first.
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/prio/esm.mjs");
    let pkg = TsPackageDefinition::new("prio", "/workspace/nm/prio").with_export(
        ".",
        make_target(&[("types", "./types.d.ts"), ("import", "./esm.mjs")], None),
    );
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(&enrichment_import("prio"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.selected_condition.as_deref(), Some("import"));
}

// ===========================================================================
// Section 18: resolve() — path alias
// ===========================================================================

#[test]
fn enrichment_resolve_path_alias_wildcard() {
    let mut paths = BTreeMap::new();
    paths.insert("@helpers/*".to_string(), vec!["src/helpers/*".to_string()]);
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/ws".to_string(),
        paths,
        ..Default::default()
    });
    resolver.register_file("/ws/src/helpers/math.ts");
    let outcome = resolver
        .resolve(&enrichment_import("@helpers/math"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/ws/src/helpers/math.ts");
}

#[test]
fn enrichment_resolve_path_alias_multiple_replacements_first_found() {
    let mut paths = BTreeMap::new();
    paths.insert(
        "@lib/*".to_string(),
        vec!["src/lib/*".to_string(), "lib/*".to_string()],
    );
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/ws".to_string(),
        paths,
        ..Default::default()
    });
    resolver.register_file("/ws/src/lib/foo.ts");
    let outcome = resolver
        .resolve(&enrichment_import("@lib/foo"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/ws/src/lib/foo.ts");
}

#[test]
fn enrichment_resolve_path_alias_fallback_to_second_replacement() {
    let mut paths = BTreeMap::new();
    paths.insert(
        "@lib/*".to_string(),
        vec!["src/lib/*".to_string(), "lib/*".to_string()],
    );
    let mut resolver = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/ws".to_string(),
        paths,
        ..Default::default()
    });
    // Only register in lib/ (second replacement)
    resolver.register_file("/ws/lib/bar.ts");
    let outcome = resolver
        .resolve(&enrichment_import("@lib/bar"), &enrichment_ctx())
        .unwrap();
    assert_eq!(outcome.resolved_path, "/ws/lib/bar.ts");
}

// ===========================================================================
// Section 19: resolve() — require extension probing
// ===========================================================================

#[test]
fn enrichment_resolve_require_cts_extension() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/cfg.cts");
    let req = enrichment_require("./cfg").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/cfg.cts");
}

#[test]
fn enrichment_resolve_require_cjs_extension() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/legacy.cjs");
    let req = enrichment_require("./legacy").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/legacy.cjs");
}

#[test]
fn enrichment_resolve_require_index_cts() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/lib/index.cts");
    let req = enrichment_require("./lib").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/lib/index.cts");
}

// ===========================================================================
// Section 20: Trace events within resolutions
// ===========================================================================

#[test]
fn enrichment_resolve_success_traces_contain_context_ids() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/a.ts");
    let req = enrichment_import("./a").with_referrer("/workspace/src/main.ts");
    let ctx = enrichment_ctx();
    let outcome = resolver.resolve(&req, &ctx).unwrap();
    for trace in &outcome.traces {
        assert_eq!(trace.trace_id, "trace-enr");
        assert_eq!(trace.decision_id, "decision-enr");
        assert_eq!(trace.policy_id, "policy-enr");
    }
}

#[test]
fn enrichment_resolve_error_traces_include_deny_outcome() {
    let resolver = enrichment_resolver();
    let req = enrichment_import("");
    let err = resolver.resolve(&req, &enrichment_ctx()).unwrap_err();
    assert!(err.traces.iter().any(|t| t.outcome == "deny"));
}

#[test]
fn enrichment_resolve_traces_component_is_ts_module_resolver() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/b.ts");
    let req = enrichment_import("./b").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    for trace in &outcome.traces {
        assert_eq!(trace.component, "ts_module_resolver");
    }
}

// ===========================================================================
// Section 21: TsResolutionDriftClass and classify_resolution_drift
// ===========================================================================

#[test]
fn enrichment_drift_no_drift() {
    let r = classify_resolution_drift(
        &["a".to_string(), "b".to_string()],
        &["a".to_string(), "b".to_string()],
    );
    assert!(!r.drift_detected);
    assert_eq!(r.class, TsResolutionDriftClass::NoDrift);
    assert!(!r.remediation.is_empty());
}

#[test]
fn enrichment_drift_candidate_order_mismatch() {
    let r = classify_resolution_drift(
        &["a".to_string(), "b".to_string()],
        &["b".to_string(), "a".to_string()],
    );
    assert!(r.drift_detected);
    assert_eq!(r.class, TsResolutionDriftClass::CandidateOrderMismatch);
}

#[test]
fn enrichment_drift_missing_target() {
    let r = classify_resolution_drift(
        &["a".to_string(), "b".to_string(), "c".to_string()],
        &["a".to_string()],
    );
    assert_eq!(r.class, TsResolutionDriftClass::MissingTarget);
}

#[test]
fn enrichment_drift_extra_target() {
    let r = classify_resolution_drift(&["a".to_string()], &["a".to_string(), "b".to_string()]);
    assert_eq!(r.class, TsResolutionDriftClass::ExtraTarget);
}

#[test]
fn enrichment_drift_full_mismatch() {
    let r = classify_resolution_drift(&["x".to_string()], &["y".to_string()]);
    assert_eq!(r.class, TsResolutionDriftClass::FullMismatch);
}

#[test]
fn enrichment_drift_empty_both_no_drift() {
    let r = classify_resolution_drift(&[], &[]);
    assert!(!r.drift_detected);
    assert_eq!(r.class, TsResolutionDriftClass::NoDrift);
}

#[test]
fn enrichment_drift_report_serde_roundtrip() {
    let r = classify_resolution_drift(&["a".to_string()], &["b".to_string()]);
    let json = serde_json::to_string(&r).unwrap();
    let back: TsResolutionDriftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_drift_class_all_variants_serde() {
    let variants = [
        TsResolutionDriftClass::NoDrift,
        TsResolutionDriftClass::CandidateOrderMismatch,
        TsResolutionDriftClass::MissingTarget,
        TsResolutionDriftClass::ExtraTarget,
        TsResolutionDriftClass::FullMismatch,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: TsResolutionDriftClass = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_drift_report_preserves_reference_and_observed() {
    let ref_c = vec!["x".to_string(), "y".to_string()];
    let obs_c = vec!["y".to_string(), "z".to_string()];
    let r = classify_resolution_drift(&ref_c, &obs_c);
    assert_eq!(r.reference_candidates, ref_c);
    assert_eq!(r.observed_candidates, obs_c);
}

#[test]
fn enrichment_drift_remediation_varies_by_class() {
    let no_drift = classify_resolution_drift(&["a".to_string()], &["a".to_string()]);
    let mismatch = classify_resolution_drift(&["a".to_string()], &["b".to_string()]);
    assert_ne!(no_drift.remediation, mismatch.remediation);
}

// ===========================================================================
// Section 22: TsResolutionIndexFallbackReason stable codes exhaustive
// ===========================================================================

#[test]
fn enrichment_fallback_reason_artifact_age_exceeded() {
    assert_eq!(
        TsResolutionIndexFallbackReason::ArtifactAgeExceeded.stable_code(),
        "FE-TSRES-IDX-0001"
    );
}

#[test]
fn enrichment_fallback_reason_workspace_fingerprint_mismatch() {
    assert_eq!(
        TsResolutionIndexFallbackReason::WorkspaceFingerprintMismatch.stable_code(),
        "FE-TSRES-IDX-0002"
    );
}

#[test]
fn enrichment_fallback_reason_index_fingerprint_mismatch() {
    assert_eq!(
        TsResolutionIndexFallbackReason::IndexFingerprintMismatch.stable_code(),
        "FE-TSRES-IDX-0003"
    );
}

#[test]
fn enrichment_fallback_reason_collision_search_exhausted() {
    assert_eq!(
        TsResolutionIndexFallbackReason::CollisionSearchExhausted.stable_code(),
        "FE-TSRES-IDX-0004"
    );
}

#[test]
fn enrichment_fallback_reason_unsupported_wildcard_export() {
    assert_eq!(
        TsResolutionIndexFallbackReason::UnsupportedWildcardExport.stable_code(),
        "FE-TSRES-IDX-0005"
    );
}

#[test]
fn enrichment_fallback_reason_package_missing_from_index() {
    assert_eq!(
        TsResolutionIndexFallbackReason::PackageMissingFromIndex.stable_code(),
        "FE-TSRES-IDX-0006"
    );
}

#[test]
fn enrichment_fallback_reason_export_missing_from_index() {
    assert_eq!(
        TsResolutionIndexFallbackReason::ExportMissingFromIndex.stable_code(),
        "FE-TSRES-IDX-0007"
    );
}

#[test]
fn enrichment_fallback_reason_serde_roundtrip_all() {
    let variants = [
        TsResolutionIndexFallbackReason::ArtifactAgeExceeded,
        TsResolutionIndexFallbackReason::WorkspaceFingerprintMismatch,
        TsResolutionIndexFallbackReason::IndexFingerprintMismatch,
        TsResolutionIndexFallbackReason::CollisionSearchExhausted,
        TsResolutionIndexFallbackReason::UnsupportedWildcardExport,
        TsResolutionIndexFallbackReason::PackageMissingFromIndex,
        TsResolutionIndexFallbackReason::ExportMissingFromIndex,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: TsResolutionIndexFallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// Section 23: TsResolutionIndexBuildPolicy
// ===========================================================================

#[test]
fn enrichment_index_build_policy_default() {
    let policy = TsResolutionIndexBuildPolicy::default();
    assert_eq!(policy.max_salt_attempts, 4_096);
}

#[test]
fn enrichment_index_build_policy_serde_roundtrip() {
    let policy = TsResolutionIndexBuildPolicy {
        max_salt_attempts: 42,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: TsResolutionIndexBuildPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy.max_salt_attempts, back.max_salt_attempts);
}

// ===========================================================================
// Section 24: Index bundle — build, validate, determinism
// ===========================================================================

#[test]
fn enrichment_index_bundle_deterministic() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/dist/index.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./dist/index.mjs")], None)),
    );
    let a = resolver.build_resolution_index_bundle("2026-03-12T00:00:00Z", 1000);
    let b = resolver.build_resolution_index_bundle("2026-03-12T00:00:00Z", 1000);
    assert_eq!(a, b);
    assert_eq!(
        a.module_index_identity_report.index_fingerprint,
        b.module_index_identity_report.index_fingerprint,
    );
}

#[test]
fn enrichment_index_bundle_different_timestamp_yields_different_fingerprint_only_if_content_differs()
 {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/dist/index.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./dist/index.mjs")], None)),
    );
    let a = resolver.build_resolution_index_bundle("2026-03-12T00:00:00Z", 1000);
    let b = resolver.build_resolution_index_bundle("2026-03-12T01:00:00Z", 2000);
    // Workspace fingerprint stays the same since config/files/packages unchanged.
    assert_eq!(
        a.module_index_identity_report.workspace_fingerprint,
        b.module_index_identity_report.workspace_fingerprint,
    );
}

#[test]
fn enrichment_index_bundle_schema_versions() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("p", "/workspace/nm/p")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert!(!bundle.module_art_index_report.schema_version.is_empty());
    assert!(!bundle.export_map_hash_catalog.schema_version.is_empty());
    assert!(
        !bundle
            .module_index_identity_report
            .schema_version
            .is_empty()
    );
}

#[test]
fn enrichment_index_bundle_package_count() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("a", "/workspace/nm/a")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    resolver.register_package(
        TsPackageDefinition::new("b", "/workspace/nm/b")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert_eq!(bundle.module_art_index_report.package_count, 2);
    assert_eq!(bundle.export_map_hash_catalog.packages.len(), 2);
}

#[test]
fn enrichment_index_bundle_empty_packages() {
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert_eq!(bundle.module_art_index_report.package_count, 0);
    assert!(bundle.export_map_hash_catalog.packages.is_empty());
}

// ===========================================================================
// Section 25: Index validation
// ===========================================================================

#[test]
fn enrichment_index_validation_accepted_when_fresh() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/i.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-03-12T00:00:00Z", 1000);
    let report = resolver.validate_resolution_index_bundle(&bundle, 1050, 3600);
    assert!(report.accepted);
    assert!(report.reason.is_none());
}

#[test]
fn enrichment_index_validation_rejected_when_stale() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/i.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-03-12T00:00:00Z", 1000);
    let report = resolver.validate_resolution_index_bundle(&bundle, 5000, 60);
    assert!(!report.accepted);
    assert_eq!(
        report.reason,
        Some(TsResolutionIndexFallbackReason::ArtifactAgeExceeded)
    );
}

#[test]
fn enrichment_index_validation_rejected_workspace_mismatch() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/i.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-03-12T00:00:00Z", 1000);

    // Now add a file to change the workspace fingerprint
    resolver.register_file("/workspace/nm/react/extra.mjs");
    let report = resolver.validate_resolution_index_bundle(&bundle, 1050, 3600);
    assert!(!report.accepted);
    assert_eq!(
        report.reason,
        Some(TsResolutionIndexFallbackReason::WorkspaceFingerprintMismatch),
    );
}

#[test]
fn enrichment_index_validation_report_serde_roundtrip() {
    let report = TsResolutionIndexValidationReport {
        accepted: false,
        reason: Some(TsResolutionIndexFallbackReason::ArtifactAgeExceeded),
        detail: "too old".to_string(),
        expected_workspace_fingerprint: "aaa".to_string(),
        observed_workspace_fingerprint: "bbb".to_string(),
        artifact_age_seconds: 9999,
        max_age_seconds: 3600,
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: TsResolutionIndexValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Section 26: resolve_with_index_or_fallback
// ===========================================================================

#[test]
fn enrichment_resolve_with_index_matches_direct() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/dist/index.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./dist/index.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 100);
    let ctx = enrichment_ctx();
    let direct = resolver.resolve(&enrichment_import("react"), &ctx).unwrap();
    let indexed = resolver
        .resolve_with_index_or_fallback(&enrichment_import("react"), &ctx, &bundle, 200, 3600)
        .unwrap();
    assert_eq!(direct.resolved_path, indexed.resolved_path);
}

#[test]
fn enrichment_resolve_with_index_falls_back_on_stale_bundle() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/dist/index.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./dist/index.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 10);
    let ctx = enrichment_ctx();
    // max_age = 1, current_time = 5000 => stale
    let indexed = resolver
        .resolve_with_index_or_fallback(&enrichment_import("react"), &ctx, &bundle, 5000, 1)
        .unwrap();
    assert_eq!(indexed.resolved_path, "/workspace/nm/react/dist/index.mjs");
}

#[test]
fn enrichment_resolve_with_index_relative_specifier_falls_back() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/a.ts");
    resolver.register_package(
        TsPackageDefinition::new("dummy", "/workspace/nm/dummy")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 100);
    let ctx = enrichment_ctx();
    let req = enrichment_import("./a").with_referrer("/workspace/src/main.ts");
    let result = resolver
        .resolve_with_index_or_fallback(&req, &ctx, &bundle, 200, 3600)
        .unwrap();
    assert_eq!(result.resolved_path, "/workspace/src/a.ts");
}

#[test]
fn enrichment_resolve_with_index_empty_specifier_falls_back_to_error() {
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 100);
    let ctx = enrichment_ctx();
    let req = enrichment_import("");
    let err = resolver
        .resolve_with_index_or_fallback(&req, &ctx, &bundle, 200, 3600)
        .unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
}

// ===========================================================================
// Section 27: Index bundle ART trie
// ===========================================================================

#[test]
fn enrichment_art_index_lookup_package() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let terminal = bundle.module_art_index_report.lookup_package("react");
    assert!(terminal.is_some());
    let t = terminal.unwrap();
    assert_eq!(t.package_name, "react");
    assert_eq!(t.export_count, 1);
}

#[test]
fn enrichment_art_index_lookup_missing_package() {
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert!(
        bundle
            .module_art_index_report
            .lookup_package("nonexist")
            .is_none()
    );
}

#[test]
fn enrichment_art_index_scoped_package_lookup() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("@scope/pkg", "/workspace/nm/@scope/pkg")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let terminal = bundle.module_art_index_report.lookup_package("@scope/pkg");
    assert!(terminal.is_some());
    assert_eq!(terminal.unwrap().package_name, "@scope/pkg");
}

#[test]
fn enrichment_art_index_node_count() {
    let mut resolver = enrichment_resolver();
    // "ab" and "ac" share the 'a' prefix node
    resolver.register_package(
        TsPackageDefinition::new("ab", "/workspace/nm/ab")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    resolver.register_package(
        TsPackageDefinition::new("ac", "/workspace/nm/ac")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    // root -> 'a' -> 'b' terminal, root -> 'a' -> 'c' terminal
    // root(0), a(1), b(2), c(3) = 4 nodes
    assert_eq!(bundle.module_art_index_report.node_count, 4);
    assert_eq!(bundle.module_art_index_report.terminal_count, 2);
}

// ===========================================================================
// Section 28: Export map hash catalog
// ===========================================================================

#[test]
fn enrichment_catalog_package_lookup() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let pkg = bundle.export_map_hash_catalog.package("react");
    assert!(pkg.is_some());
    assert_eq!(pkg.unwrap().package_name, "react");
}

#[test]
fn enrichment_catalog_package_not_found() {
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert!(bundle.export_map_hash_catalog.package("missing").is_none());
}

#[test]
fn enrichment_catalog_exact_export_lookup() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None))
            .with_export(
                "./jsx-runtime",
                make_target(&[("import", "./jsx.mjs")], None),
            ),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let pkg = bundle.export_map_hash_catalog.package("react").unwrap();
    let entry = pkg.lookup_exact_export(".");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().key, ".");
}

#[test]
fn enrichment_catalog_hot_subpath_lookup() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None))
            .with_export(
                "./jsx-runtime",
                make_target(&[("import", "./jsx.mjs")], None),
            ),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let pkg = bundle.export_map_hash_catalog.package("react").unwrap();
    let entry = pkg.lookup_hot_subpath("./jsx-runtime");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().subpath, "./jsx-runtime");
}

#[test]
fn enrichment_catalog_wildcard_exports_recorded() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("wc", "/workspace/nm/wc")
            .with_export("./*", make_target(&[("import", "./dist/*.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let pkg = bundle.export_map_hash_catalog.package("wc").unwrap();
    assert_eq!(pkg.wildcard_exports.len(), 1);
    assert_eq!(pkg.wildcard_exports[0].pattern, "./*");
    assert!(
        pkg.fallback_reasons
            .contains(&TsResolutionIndexFallbackReason::UnsupportedWildcardExport)
    );
}

#[test]
fn enrichment_catalog_collision_search_exhausted_with_zero_attempts() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None))
            .with_export("./extra", make_target(&[("import", "./e.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle_with_policy(
        "2026-01-01T00:00:00Z",
        0,
        &TsResolutionIndexBuildPolicy {
            max_salt_attempts: 0,
        },
    );
    let pkg = bundle.export_map_hash_catalog.package("react").unwrap();
    assert!(pkg.exact_export_mphf.is_none());
    assert!(
        pkg.fallback_reasons
            .contains(&TsResolutionIndexFallbackReason::CollisionSearchExhausted)
    );
}

// ===========================================================================
// Section 29: TsResolutionArtifactPaths and TsResolutionRunManifest serde
// ===========================================================================

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let paths = TsResolutionArtifactPaths {
        run_manifest: "run_manifest.json".to_string(),
        events: "events.jsonl".to_string(),
        commands: "commands.txt".to_string(),
        ts_resolution_trace: "ts_resolution_trace.jsonl".to_string(),
        drift_report: "drift_report.json".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: TsResolutionArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let manifest = TsResolutionRunManifest {
        schema_version: "v1".to_string(),
        scenario_id: "s1".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        trace_count: 42,
        drift_class: TsResolutionDriftClass::ExtraTarget,
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

// ===========================================================================
// Section 30: write_ts_resolution_artifacts
// ===========================================================================

#[test]
fn enrichment_write_artifacts_creates_all_files() {
    let dir = unique_dir("write_artifacts");
    let drift = classify_resolution_drift(&["a".to_string()], &["a".to_string()]);
    let traces = vec![TsResolutionTraceEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: "none".to_string(),
        detail: "test".to_string(),
        candidate: None,
    }];
    let result = write_ts_resolution_artifacts(
        &dir,
        "scn-1",
        "2026-01-01T00:00:00Z",
        &["cmd1".to_string()],
        &traces,
        &drift,
    );
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.trace_count, 1);
    assert!(dir.join("run_manifest.json").exists());
    assert!(dir.join("events.jsonl").exists());
    assert!(dir.join("commands.txt").exists());
    assert!(dir.join("drift_report.json").exists());
    assert!(dir.join("ts_resolution_trace.jsonl").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_write_artifacts_manifest_is_valid_json() {
    let dir = unique_dir("write_manifest_json");
    let drift = classify_resolution_drift(&[], &[]);
    let result =
        write_ts_resolution_artifacts(&dir, "scn", "2026-01-01T00:00:00Z", &[], &[], &drift);
    assert!(result.is_ok());
    let raw = fs::read_to_string(dir.join("run_manifest.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(parsed.is_object());
    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// Section 31: write_ts_resolution_index_artifacts
// ===========================================================================

#[test]
fn enrichment_write_index_artifacts_creates_all_files() {
    let dir = unique_dir("write_index_artifacts");
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/i.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 100);
    let validation = resolver.validate_resolution_index_bundle(&bundle, 200, 3600);
    let step_logs = vec![TsResolutionIndexStepLog {
        name: "step one".to_string(),
        contents: "log data".to_string(),
    }];
    let result = write_ts_resolution_index_artifacts(
        &dir,
        "idx-scn",
        &["cmd".to_string()],
        &[],
        &bundle,
        &validation,
        &step_logs,
    );
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert!(dir.join("run_manifest.json").exists());
    assert!(dir.join("events.jsonl").exists());
    assert!(dir.join("commands.txt").exists());
    assert!(dir.join("trace_ids.json").exists());
    assert!(dir.join("module_art_index_report.json").exists());
    assert!(dir.join("export_map_hash_catalog.json").exists());
    assert!(dir.join("module_index_identity_report.json").exists());
    assert!(dir.join("step_logs").is_dir());
    assert!(!manifest.workspace_fingerprint.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enrichment_write_index_artifacts_step_log_files_created() {
    let dir = unique_dir("write_index_step_logs");
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let validation = resolver.validate_resolution_index_bundle(&bundle, 10, 3600);
    let step_logs = vec![
        TsResolutionIndexStepLog {
            name: "init".to_string(),
            contents: "init done".to_string(),
        },
        TsResolutionIndexStepLog {
            name: "build".to_string(),
            contents: "build done".to_string(),
        },
    ];
    let result = write_ts_resolution_index_artifacts(
        &dir,
        "scn",
        &[],
        &[],
        &bundle,
        &validation,
        &step_logs,
    );
    assert!(result.is_ok());
    let step_dir = dir.join("step_logs");
    // Count files in step_logs directory
    let entries: Vec<_> = fs::read_dir(&step_dir).unwrap().collect();
    assert_eq!(entries.len(), 2);
    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// Section 32: TsResolutionIndexArtifactPaths serde
// ===========================================================================

#[test]
fn enrichment_index_artifact_paths_serde_roundtrip() {
    let paths = TsResolutionIndexArtifactPaths {
        run_manifest: "rm.json".to_string(),
        events: "ev.jsonl".to_string(),
        commands: "cmd.txt".to_string(),
        trace_ids: "tid.json".to_string(),
        module_art_index_report: "art.json".to_string(),
        export_map_hash_catalog: "cat.json".to_string(),
        module_index_identity_report: "id.json".to_string(),
        step_logs_dir: "steps".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: TsResolutionIndexArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ===========================================================================
// Section 33: TsResolutionIndexRunManifest serde
// ===========================================================================

#[test]
fn enrichment_index_run_manifest_serde_roundtrip() {
    let manifest = TsResolutionIndexRunManifest {
        schema_version: "v1".to_string(),
        scenario_id: "scn".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        generated_at_unix_seconds: 1000,
        trace_count: 5,
        workspace_fingerprint: "ws-fp".to_string(),
        index_fingerprint: "idx-fp".to_string(),
        validation: TsResolutionIndexValidationReport {
            accepted: true,
            reason: None,
            detail: "ok".to_string(),
            expected_workspace_fingerprint: "a".to_string(),
            observed_workspace_fingerprint: "a".to_string(),
            artifact_age_seconds: 10,
            max_age_seconds: 3600,
        },
        artifact_paths: TsResolutionIndexArtifactPaths {
            run_manifest: "rm.json".to_string(),
            events: "ev.jsonl".to_string(),
            commands: "cmd.txt".to_string(),
            trace_ids: "tid.json".to_string(),
            module_art_index_report: "art.json".to_string(),
            export_map_hash_catalog: "cat.json".to_string(),
            module_index_identity_report: "id.json".to_string(),
            step_logs_dir: "steps".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TsResolutionIndexRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ===========================================================================
// Section 34: TsResolutionIndexTraceIds serde
// ===========================================================================

#[test]
fn enrichment_trace_ids_serde_roundtrip() {
    let ids = TsResolutionIndexTraceIds {
        schema_version: "v1".to_string(),
        component: "ts_module_resolver".to_string(),
        trace_ids: vec!["t1".to_string(), "t2".to_string()],
        decision_ids: vec!["d1".to_string()],
        policy_ids: vec!["p1".to_string()],
    };
    let json = serde_json::to_string(&ids).unwrap();
    let back: TsResolutionIndexTraceIds = serde_json::from_str(&json).unwrap();
    assert_eq!(ids, back);
}

// ===========================================================================
// Section 35: TsResolutionIndexStepLog serde
// ===========================================================================

#[test]
fn enrichment_step_log_serde_roundtrip() {
    let log = TsResolutionIndexStepLog {
        name: "build".to_string(),
        contents: "step completed".to_string(),
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: TsResolutionIndexStepLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

// ===========================================================================
// Section 36: TsPackageArtNode, TsPackageArtEdge, TsPackageArtTerminal serde
// ===========================================================================

#[test]
fn enrichment_art_terminal_serde_roundtrip() {
    let t = TsPackageArtTerminal {
        package_name: "react".to_string(),
        package_root: "/nm/react".to_string(),
        export_count: 3,
        hot_subpath_count: 1,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: TsPackageArtTerminal = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrichment_art_edge_serde_roundtrip() {
    let e = TsPackageArtEdge {
        label: "r".to_string(),
        child_index: 5,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: TsPackageArtEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_art_node_serde_roundtrip() {
    let node = TsPackageArtNode {
        node_id: 0,
        fragment: "".to_string(),
        terminal: None,
        children: vec![TsPackageArtEdge {
            label: "a".to_string(),
            child_index: 1,
        }],
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: TsPackageArtNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

// ===========================================================================
// Section 37: TsPerfectHashSlot and TsPerfectHashLayout serde
// ===========================================================================

#[test]
fn enrichment_perfect_hash_slot_serde_roundtrip() {
    let slot = TsPerfectHashSlot {
        slot: 3,
        key: ".".to_string(),
        key_fingerprint: "fp".to_string(),
    };
    let json = serde_json::to_string(&slot).unwrap();
    let back: TsPerfectHashSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(slot, back);
}

#[test]
fn enrichment_perfect_hash_layout_serde_roundtrip() {
    let layout = TsPerfectHashLayout {
        salt: 42,
        table_size: 2,
        slots: vec![
            TsPerfectHashSlot {
                slot: 0,
                key: "a".to_string(),
                key_fingerprint: "fp_a".to_string(),
            },
            TsPerfectHashSlot {
                slot: 1,
                key: "b".to_string(),
                key_fingerprint: "fp_b".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&layout).unwrap();
    let back: TsPerfectHashLayout = serde_json::from_str(&json).unwrap();
    assert_eq!(layout, back);
}

// ===========================================================================
// Section 38: TsIndexedExportEntry, TsIndexedSubpathEntry, TsWildcardExportEntry serde
// ===========================================================================

#[test]
fn enrichment_indexed_export_entry_serde_roundtrip() {
    let entry = TsIndexedExportEntry {
        key: ".".to_string(),
        key_fingerprint: "kfp".to_string(),
        target_fingerprint: "tfp".to_string(),
        export_target: make_target(&[("import", "./i.mjs")], None),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: TsIndexedExportEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_indexed_subpath_entry_serde_roundtrip() {
    let entry = TsIndexedSubpathEntry {
        subpath: "./jsx-runtime".to_string(),
        key_fingerprint: "kfp".to_string(),
        target_fingerprint: "tfp".to_string(),
        export_target: make_target(&[("import", "./jsx.mjs")], None),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: TsIndexedSubpathEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_wildcard_export_entry_serde_roundtrip() {
    let entry = TsWildcardExportEntry {
        pattern: "./*".to_string(),
        pattern_fingerprint: "pfp".to_string(),
        target_fingerprint: "tfp".to_string(),
        export_target: make_target(&[("import", "./dist/*.mjs")], None),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: TsWildcardExportEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// Section 39: TsExportMapHashCatalogPackage serde
// ===========================================================================

#[test]
fn enrichment_catalog_package_serde_roundtrip() {
    let pkg = TsExportMapHashCatalogPackage {
        package_name: "react".to_string(),
        package_root: "/nm/react".to_string(),
        exact_exports: vec![],
        exact_export_mphf: None,
        hot_subpaths: vec![],
        hot_subpath_mphf: None,
        wildcard_exports: vec![],
        fallback_reasons: vec![TsResolutionIndexFallbackReason::CollisionSearchExhausted],
    };
    let json = serde_json::to_string(&pkg).unwrap();
    let back: TsExportMapHashCatalogPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, back);
}

// ===========================================================================
// Section 40: TsExportMapHashCatalog serde
// ===========================================================================

#[test]
fn enrichment_catalog_serde_roundtrip() {
    let catalog = TsExportMapHashCatalog {
        schema_version: "v1".to_string(),
        component: "c".to_string(),
        workspace_fingerprint: "wfp".to_string(),
        indexed_package_count: 1,
        fallback_package_count: 0,
        packages: vec![],
    };
    let json = serde_json::to_string(&catalog).unwrap();
    let back: TsExportMapHashCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, back);
}

// ===========================================================================
// Section 41: TsIndexFallbackPackage serde
// ===========================================================================

#[test]
fn enrichment_index_fallback_package_serde_roundtrip() {
    let pkg = TsIndexFallbackPackage {
        package_name: "bad-pkg".to_string(),
        reasons: vec![
            TsResolutionIndexFallbackReason::CollisionSearchExhausted,
            TsResolutionIndexFallbackReason::UnsupportedWildcardExport,
        ],
    };
    let json = serde_json::to_string(&pkg).unwrap();
    let back: TsIndexFallbackPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, back);
}

// ===========================================================================
// Section 42: TsModuleIndexIdentityReport serde
// ===========================================================================

#[test]
fn enrichment_identity_report_serde_roundtrip() {
    let report = TsModuleIndexIdentityReport {
        schema_version: "v1".to_string(),
        component: "c".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        generated_at_unix_seconds: 100,
        default_max_age_seconds: 3600,
        config_fingerprint: "cfg_fp".to_string(),
        files_fingerprint: "files_fp".to_string(),
        packages_fingerprint: "pkg_fp".to_string(),
        workspace_fingerprint: "ws_fp".to_string(),
        package_art_fingerprint: "art_fp".to_string(),
        export_map_hash_catalog_fingerprint: "cat_fp".to_string(),
        index_fingerprint: "idx_fp".to_string(),
        fallback_packages: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: TsModuleIndexIdentityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Section 43: TsModuleResolutionIndexBundle serde
// ===========================================================================

#[test]
fn enrichment_index_bundle_serde_roundtrip() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let json = serde_json::to_string(&bundle).unwrap();
    let back: TsModuleResolutionIndexBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ===========================================================================
// Section 44: TsModuleArtIndexReport serde
// ===========================================================================

#[test]
fn enrichment_art_index_report_serde_roundtrip() {
    let report = TsModuleArtIndexReport {
        schema_version: "v1".to_string(),
        component: "c".to_string(),
        workspace_fingerprint: "wf".to_string(),
        package_count: 0,
        node_count: 1,
        terminal_count: 0,
        nodes: vec![TsPackageArtNode {
            node_id: 0,
            fragment: "".to_string(),
            terminal: None,
            children: vec![],
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: TsModuleArtIndexReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Section 45: ContentHash integration with fingerprints
// ===========================================================================

#[test]
fn enrichment_content_hash_deterministic() {
    let a = ContentHash::compute(b"hello");
    let b = ContentHash::compute(b"hello");
    assert_eq!(a, b);
}

#[test]
fn enrichment_content_hash_differs_for_different_input() {
    let a = ContentHash::compute(b"hello");
    let b = ContentHash::compute(b"world");
    assert_ne!(a, b);
}

#[test]
fn enrichment_fixed_point_millionths_constant() {
    // Validate the fixed-point constant
    assert_eq!(FIXED_POINT_ONE, 1_000_000);
    let half = FIXED_POINT_ONE / 2;
    assert_eq!(half, 500_000);
}

// ===========================================================================
// Section 46: Determinism of resolver across multiple registrations
// ===========================================================================

#[test]
fn enrichment_resolver_deterministic_file_order() {
    let mut r1 = enrichment_resolver();
    r1.register_file("src/a.ts");
    r1.register_file("src/b.ts");
    let mut r2 = enrichment_resolver();
    r2.register_file("src/b.ts");
    r2.register_file("src/a.ts");
    // BTreeSet ensures deterministic ordering regardless of insertion order
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn enrichment_resolver_deterministic_package_order() {
    let mut r1 = enrichment_resolver();
    r1.register_package(TsPackageDefinition::new("a", "/workspace/nm/a"));
    r1.register_package(TsPackageDefinition::new("b", "/workspace/nm/b"));
    let mut r2 = enrichment_resolver();
    r2.register_package(TsPackageDefinition::new("b", "/workspace/nm/b"));
    r2.register_package(TsPackageDefinition::new("a", "/workspace/nm/a"));
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2);
}

// ===========================================================================
// Section 47: Edge cases in resolution
// ===========================================================================

#[test]
fn enrichment_resolve_exact_file_match_no_extension_probe() {
    let mut resolver = enrichment_resolver();
    // Register a file that matches the specifier exactly (no extension needed)
    resolver.register_file("/workspace/src/exact");
    let req = enrichment_import("./exact").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/exact");
}

#[test]
fn enrichment_resolve_multiple_extensions_picks_first() {
    let mut resolver = enrichment_resolver();
    // Register both .ts and .tsx — .ts appears first in import_extensions
    resolver.register_file("/workspace/src/comp.ts");
    resolver.register_file("/workspace/src/comp.tsx");
    let req = enrichment_import("./comp").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/comp.ts");
}

#[test]
fn enrichment_resolve_index_file_only_after_direct_probes() {
    let mut resolver = enrichment_resolver();
    // Only register index.ts (not direct .ts or .tsx), so index.ts is the fallback
    resolver.register_file("/workspace/src/dir/index.ts");
    let req = enrichment_import("./dir").with_referrer("/workspace/src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/dir/index.ts");
}

#[test]
fn enrichment_resolve_dot_dot_at_root_stays_at_root() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/root.ts");
    let req = enrichment_import("../../root").with_referrer("/workspace/a.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/root.ts");
}

#[test]
fn enrichment_resolve_referrer_relative_path() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/src/util.ts");
    let req = enrichment_import("./util").with_referrer("src/main.ts");
    let outcome = resolver.resolve(&req, &enrichment_ctx()).unwrap();
    assert_eq!(outcome.resolved_path, "/workspace/src/util.ts");
}

// ===========================================================================
// Section 48: Identity report fields populated correctly from build
// ===========================================================================

#[test]
fn enrichment_identity_report_default_max_age() {
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert_eq!(
        bundle.module_index_identity_report.default_max_age_seconds,
        3600
    );
}

#[test]
fn enrichment_identity_report_generated_at_utc_preserved() {
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-06-15T12:30:00Z", 999);
    assert_eq!(
        bundle.module_index_identity_report.generated_at_utc,
        "2026-06-15T12:30:00Z"
    );
    assert_eq!(
        bundle
            .module_index_identity_report
            .generated_at_unix_seconds,
        999
    );
}

#[test]
fn enrichment_identity_report_component_is_ts_module_resolver() {
    let resolver = enrichment_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert_eq!(
        bundle.module_index_identity_report.component,
        "ts_module_resolver"
    );
    assert_eq!(
        bundle.module_art_index_report.component,
        "ts_module_resolver"
    );
    assert_eq!(
        bundle.export_map_hash_catalog.component,
        "ts_module_resolver"
    );
}

#[test]
fn enrichment_identity_report_fallback_packages_populated() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("wc", "/workspace/nm/wc")
            .with_export("./*", make_target(&[("import", "./dist/*.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert!(
        !bundle
            .module_index_identity_report
            .fallback_packages
            .is_empty()
    );
    assert_eq!(
        bundle.module_index_identity_report.fallback_packages[0].package_name,
        "wc",
    );
}

#[test]
fn enrichment_identity_report_no_fallback_when_all_exact() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("clean", "/workspace/nm/clean")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert!(
        bundle
            .module_index_identity_report
            .fallback_packages
            .is_empty()
    );
}

// ===========================================================================
// Section 49: Various fingerprint consistency tests
// ===========================================================================

#[test]
fn enrichment_workspace_fingerprint_changes_with_config() {
    let r1 = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/ws".to_string(),
        ..Default::default()
    });
    let r2 = DeterministicTsModuleResolver::new(TsModuleResolutionConfig {
        project_root: "/other".to_string(),
        ..Default::default()
    });
    let b1 = r1.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let b2 = r2.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert_ne!(
        b1.module_index_identity_report.workspace_fingerprint,
        b2.module_index_identity_report.workspace_fingerprint,
    );
}

#[test]
fn enrichment_workspace_fingerprint_changes_with_files() {
    let mut r1 = enrichment_resolver();
    let r2 = enrichment_resolver();
    r1.register_file("src/extra.ts");
    let b1 = r1.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let b2 = r2.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert_ne!(
        b1.module_index_identity_report.workspace_fingerprint,
        b2.module_index_identity_report.workspace_fingerprint,
    );
}

#[test]
fn enrichment_workspace_fingerprint_changes_with_packages() {
    let mut r1 = enrichment_resolver();
    let r2 = enrichment_resolver();
    r1.register_package(TsPackageDefinition::new("extra", "/workspace/nm/extra"));
    let b1 = r1.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    let b2 = r2.build_resolution_index_bundle("2026-01-01T00:00:00Z", 0);
    assert_ne!(
        b1.module_index_identity_report.workspace_fingerprint,
        b2.module_index_identity_report.workspace_fingerprint,
    );
}

// ===========================================================================
// Section 50: Scoped package deep subpath resolution
// ===========================================================================

#[test]
fn enrichment_resolve_scoped_package_deep_subpath() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/@org/lib/dist/deep/utils.mjs");
    let pkg = TsPackageDefinition::new("@org/lib", "/workspace/nm/@org/lib").with_export(
        "./dist/deep/utils",
        make_target(&[("import", "./dist/deep/utils.mjs")], None),
    );
    resolver.register_package(pkg);
    let outcome = resolver
        .resolve(
            &enrichment_import("@org/lib/dist/deep/utils"),
            &enrichment_ctx(),
        )
        .unwrap();
    assert_eq!(
        outcome.resolved_path,
        "/workspace/nm/@org/lib/dist/deep/utils.mjs"
    );
}

// ===========================================================================
// Section 51: Multiple packages in same resolver
// ===========================================================================

#[test]
fn enrichment_resolve_among_multiple_packages() {
    let mut resolver = enrichment_resolver();
    resolver.register_file("/workspace/nm/react/index.mjs");
    resolver.register_file("/workspace/nm/vue/index.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/workspace/nm/react")
            .with_export(".", make_target(&[("import", "./index.mjs")], None)),
    );
    resolver.register_package(
        TsPackageDefinition::new("vue", "/workspace/nm/vue")
            .with_export(".", make_target(&[("import", "./index.mjs")], None)),
    );
    let r1 = resolver
        .resolve(&enrichment_import("react"), &enrichment_ctx())
        .unwrap();
    let r2 = resolver
        .resolve(&enrichment_import("vue"), &enrichment_ctx())
        .unwrap();
    assert_eq!(r1.resolved_path, "/workspace/nm/react/index.mjs");
    assert_eq!(r2.resolved_path, "/workspace/nm/vue/index.mjs");
    assert_eq!(r1.package_name.as_deref(), Some("react"));
    assert_eq!(r2.package_name.as_deref(), Some("vue"));
}

// ===========================================================================
// Section 52: validate_resolution_index_bundle edge cases
// ===========================================================================

#[test]
fn enrichment_validation_age_exactly_at_boundary() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("p", "/workspace/nm/p")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 1000);
    // age = 1060 - 1000 = 60, max_age = 60; age > max_age is the check
    let report = resolver.validate_resolution_index_bundle(&bundle, 1060, 60);
    // 60 > 60 is false, so should be accepted (exactly at boundary)
    assert!(report.accepted);
}

#[test]
fn enrichment_validation_age_one_over_boundary() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("p", "/workspace/nm/p")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 1000);
    // age = 1061 - 1000 = 61, max_age = 60; 61 > 60 = true => rejected
    let report = resolver.validate_resolution_index_bundle(&bundle, 1061, 60);
    assert!(!report.accepted);
    assert_eq!(
        report.reason,
        Some(TsResolutionIndexFallbackReason::ArtifactAgeExceeded)
    );
}

#[test]
fn enrichment_validation_saturating_sub_for_underflow() {
    let mut resolver = enrichment_resolver();
    resolver.register_package(
        TsPackageDefinition::new("p", "/workspace/nm/p")
            .with_export(".", make_target(&[("import", "./i.mjs")], None)),
    );
    // generated_at = 5000, current_time = 100 => saturating_sub gives 0
    let bundle = resolver.build_resolution_index_bundle("2026-01-01T00:00:00Z", 5000);
    let report = resolver.validate_resolution_index_bundle(&bundle, 100, 3600);
    // age = 0, which is <= 3600, so accepted (if fingerprint matches)
    assert!(report.accepted);
}
