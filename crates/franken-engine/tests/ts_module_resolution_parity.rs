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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ts_module_resolution::{
    DeterministicTsModuleResolver, TsModuleRequest, TsModuleResolutionConfig,
    TsModuleResolutionError, TsModuleResolutionMode, TsModuleResolutionOutcome,
    TsPackageDefinition, TsPackageExportTarget, TsRequestStyle, TsResolutionArtifactPaths,
    TsResolutionContext, TsResolutionDriftClass, TsResolutionDriftReport, TsResolutionErrorCode,
    TsResolutionRunManifest, TsResolutionTraceEvent, classify_resolution_drift,
    write_ts_resolution_artifacts,
};
use serde_json::Value;

const SCHEMA_VERSION: &str = "rgc.ts-module-resolution.parity.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_ts_module_resolution_parity_v1.json");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn context() -> TsResolutionContext {
    TsResolutionContext::new("trace-tsres-1", "decision-tsres-1", "policy-tsres-1")
}

fn base_config() -> TsModuleResolutionConfig {
    TsModuleResolutionConfig {
        project_root: "/repo".to_string(),
        base_url: ".".to_string(),
        mode: TsModuleResolutionMode::NodeNext,
        ..TsModuleResolutionConfig::default()
    }
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic from unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frx_ts_resolution_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn parse_contract() -> Value {
    serde_json::from_str(CONTRACT_JSON).expect("contract json should parse")
}

fn json_string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .expect("array field should exist")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("array entry should be string")
                .to_string()
        })
        .collect()
}

// ─── Section 1: Contract and Documentation Integrity ─────────────────

#[test]
fn rgc_202_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_TS_MODULE_RESOLUTION_PARITY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required in [
        "# RGC TS Module Resolution Parity V1",
        "## Purpose",
        "## Resolution Semantics",
        "## Drift Classification and Remediation",
        "## Artifact Contract",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(required),
            "missing required section in {}: {required}",
            path.display()
        );
    }
}

#[test]
fn rgc_202_contract_schema_and_required_fields_are_present() {
    let contract = parse_contract();

    assert_eq!(
        contract
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version should be present"),
        SCHEMA_VERSION
    );
    assert_eq!(
        contract
            .get("bead_id")
            .and_then(Value::as_str)
            .expect("bead_id should be present"),
        "bd-1lsy.3.2"
    );

    let resolution_policy = contract
        .get("resolution_policy")
        .expect("resolution_policy should exist");
    assert!(
        resolution_policy
            .get("deterministic")
            .and_then(Value::as_bool)
            .expect("deterministic should exist")
    );
    assert!(
        resolution_policy
            .get("paths_alias_support")
            .and_then(Value::as_bool)
            .expect("paths_alias_support should exist")
    );
    assert!(
        resolution_policy
            .get("base_url_fallback")
            .and_then(Value::as_bool)
            .expect("base_url_fallback should exist")
    );

    let stable_fields: BTreeSet<String> =
        json_string_array(resolution_policy, "stable_trace_fields")
            .into_iter()
            .collect();
    for required in [
        "trace_id",
        "decision_id",
        "policy_id",
        "event",
        "error_code",
    ] {
        assert!(
            stable_fields.contains(required),
            "missing trace field {required}"
        );
    }

    let parity_scenarios = contract
        .get("parity_scenarios")
        .and_then(Value::as_array)
        .expect("parity_scenarios should be array");
    assert_eq!(parity_scenarios.len(), 3);
    for scenario in parity_scenarios {
        assert!(
            scenario
                .get("required")
                .and_then(Value::as_bool)
                .expect("required should exist")
        );
        assert!(
            scenario
                .get("coverage")
                .and_then(Value::as_array)
                .map(|entries| !entries.is_empty())
                .unwrap_or(false),
            "scenario coverage must be non-empty"
        );
    }

    let artifact_contract = contract
        .get("artifact_contract")
        .expect("artifact_contract should exist");
    let required_paths: BTreeSet<String> = json_string_array(artifact_contract, "required_paths")
        .into_iter()
        .collect();
    for required in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "ts_resolution_trace.jsonl",
    ] {
        assert!(
            required_paths.contains(required),
            "missing artifact path {required}"
        );
    }

    let drift_classes: BTreeSet<String> = contract
        .get("drift_classification")
        .and_then(Value::as_array)
        .expect("drift_classification should exist")
        .iter()
        .filter_map(|entry| entry.get("class").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    for required in [
        "no_drift",
        "candidate_order_mismatch",
        "missing_target",
        "extra_target",
        "full_mismatch",
    ] {
        assert!(
            drift_classes.contains(required),
            "missing drift class {required}"
        );
    }

    let operator_verification = contract
        .get("operator_verification")
        .and_then(Value::as_array)
        .expect("operator_verification should be present");
    let verification_lines = operator_verification
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(verification_lines.contains("jq empty"));
    assert!(
        verification_lines
            .contains("cargo test -p frankenengine-engine --test ts_module_resolution_parity")
    );
}

// ─── Section 2: Resolver Core - Paths Alias and Extensions ───────────

#[test]
fn resolver_honors_paths_alias_and_extension_probe_order() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string(), ".js".to_string()];
    config.paths = BTreeMap::from([(
        "@core/*".to_string(),
        vec!["packages/core/src/*".to_string()],
    )]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/core/src/math.ts");
    resolver.register_file("/repo/packages/core/src/math.js");

    let request = TsModuleRequest::new("@core/math", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("alias-based import should resolve");

    assert_eq!(outcome.resolved_path, "/repo/packages/core/src/math.ts");

    let probes = outcome.probe_sequence();
    assert_eq!(probes[0], "/repo/packages/core/src/math");
    assert_eq!(probes[1], "/repo/packages/core/src/math.ts");

    assert!(
        outcome
            .traces
            .iter()
            .any(|event| event.event == "paths_alias_match"),
        "expected alias match trace event"
    );
}

#[test]
fn resolver_selects_package_export_condition_by_request_style() {
    let mut config = base_config();
    config.import_conditions = vec!["import".to_string(), "default".to_string()];
    config.require_conditions = vec!["require".to_string(), "default".to_string()];
    config.import_extensions = vec![".mjs".to_string(), ".js".to_string()];
    config.require_extensions = vec![".cjs".to_string(), ".js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/node_modules/toolkit/esm/index.mjs");
    resolver.register_file("/repo/node_modules/toolkit/cjs/index.cjs");
    resolver.register_file("/repo/node_modules/toolkit/dist/index.js");

    let mut condition_targets = BTreeMap::new();
    condition_targets.insert("import".to_string(), "./esm/index".to_string());
    condition_targets.insert("require".to_string(), "./cjs/index".to_string());
    condition_targets.insert("default".to_string(), "./dist/index".to_string());

    let package = TsPackageDefinition::new("toolkit", "/repo/node_modules/toolkit").with_export(
        ".",
        TsPackageExportTarget {
            condition_targets,
            fallback_target: Some("./dist/index".to_string()),
        },
    );
    resolver.register_package(package);

    let import_outcome = resolver
        .resolve(
            &TsModuleRequest::new("toolkit", TsRequestStyle::Import),
            &context(),
        )
        .expect("import should resolve");
    assert_eq!(
        import_outcome.resolved_path,
        "/repo/node_modules/toolkit/esm/index.mjs"
    );
    assert_eq!(import_outcome.selected_condition.as_deref(), Some("import"));

    let require_outcome = resolver
        .resolve(
            &TsModuleRequest::new("toolkit", TsRequestStyle::Require),
            &context(),
        )
        .expect("require should resolve");
    assert_eq!(
        require_outcome.resolved_path,
        "/repo/node_modules/toolkit/cjs/index.cjs"
    );
    assert_eq!(
        require_outcome.selected_condition.as_deref(),
        Some("require")
    );
}

#[test]
fn resolver_paths_alias_has_priority_over_base_url_fallback() {
    let mut with_alias = base_config();
    with_alias.base_url = "src".to_string();
    with_alias.paths = BTreeMap::from([(
        "utils/*".to_string(),
        vec!["../packages/utils/*".to_string()],
    )]);
    with_alias.import_extensions = vec![".ts".to_string()];

    let mut alias_resolver = DeterministicTsModuleResolver::new(with_alias);
    alias_resolver.register_file("/repo/packages/utils/math.ts");
    alias_resolver.register_file("/repo/src/utils/math.ts");

    let request = TsModuleRequest::new("utils/math", TsRequestStyle::Import);
    let alias_outcome = alias_resolver
        .resolve(&request, &context())
        .expect("alias route should win over baseUrl fallback");
    assert_eq!(alias_outcome.resolved_path, "/repo/packages/utils/math.ts");

    let mut without_alias = base_config();
    without_alias.base_url = "src".to_string();
    without_alias.paths.clear();
    without_alias.import_extensions = vec![".ts".to_string()];

    let mut fallback_resolver = DeterministicTsModuleResolver::new(without_alias);
    fallback_resolver.register_file("/repo/src/utils/math.ts");

    let fallback_outcome = fallback_resolver
        .resolve(&request, &context())
        .expect("baseUrl fallback should resolve without alias");
    assert_eq!(fallback_outcome.resolved_path, "/repo/src/utils/math.ts");
}

#[test]
fn monorepo_resolution_trace_is_deterministic_across_runs() {
    let mut config = base_config();
    config.paths = BTreeMap::from([(
        "@app/*".to_string(),
        vec![
            "apps/web/src/*".to_string(),
            "packages/shared/src/*".to_string(),
        ],
    )]);
    config.import_extensions = vec![".ts".to_string(), "/index.ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/shared/src/runtime/index.ts");

    let request = TsModuleRequest::new("@app/runtime", TsRequestStyle::Import);
    let first = resolver
        .resolve(&request, &context())
        .expect("first resolve should pass");
    let second = resolver
        .resolve(&request, &context())
        .expect("second resolve should pass");

    assert_eq!(
        first.resolved_path,
        "/repo/packages/shared/src/runtime/index.ts"
    );
    assert_eq!(first.resolved_path, second.resolved_path);
    assert_eq!(first.traces, second.traces);
}

#[test]
fn drift_classifier_and_artifact_emitter_cover_e2e_requirements() {
    let mut config = base_config();
    config.paths = BTreeMap::from([(
        "@core/*".to_string(),
        vec!["packages/core/src/*".to_string()],
    )]);
    config.import_extensions = vec![".ts".to_string(), "/index.ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/core/src/runtime/index.ts");

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("@core/runtime", TsRequestStyle::Import),
            &context(),
        )
        .expect("runtime alias should resolve");

    let reference = vec![
        "/repo/packages/core/src/runtime.ts".to_string(),
        "/repo/packages/core/src/runtime/index.ts".to_string(),
    ];
    let observed = vec![
        "/repo/packages/core/src/runtime/index.ts".to_string(),
        "/repo/packages/core/src/runtime.ts".to_string(),
    ];
    let drift = classify_resolution_drift(&reference, &observed);
    assert_eq!(drift.class, TsResolutionDriftClass::CandidateOrderMismatch);
    assert!(drift.drift_detected);
    assert!(!drift.remediation.trim().is_empty());

    let output_dir = unique_temp_dir("parity");
    fs::create_dir_all(&output_dir).expect("output dir should be created");

    let commands = vec![
        "rch exec -- cargo test -p frankenengine-engine --test ts_module_resolution_parity"
            .to_string(),
        "jq empty docs/rgc_ts_module_resolution_parity_v1.json".to_string(),
    ];

    let manifest = write_ts_resolution_artifacts(
        &output_dir,
        "monorepo-fallback-and-trace-determinism",
        "2026-02-28T06:00:00Z",
        &commands,
        &outcome.traces,
        &drift,
    )
    .expect("artifact writer should succeed");

    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    assert_eq!(
        manifest.scenario_id,
        "monorepo-fallback-and-trace-determinism"
    );
    assert_eq!(manifest.trace_count, outcome.traces.len());

    let required_files = [
        &manifest.artifact_paths.run_manifest,
        &manifest.artifact_paths.events,
        &manifest.artifact_paths.commands,
        &manifest.artifact_paths.ts_resolution_trace,
        &manifest.artifact_paths.drift_report,
    ];
    for path in required_files {
        assert!(
            output_dir.join(path).exists(),
            "missing artifact {}",
            output_dir.join(path).display()
        );
    }

    let commands_text = fs::read_to_string(output_dir.join(&manifest.artifact_paths.commands))
        .expect("commands file should be readable");
    assert!(commands_text.contains("rch exec -- cargo test"));

    let event_line_count = fs::read_to_string(output_dir.join(&manifest.artifact_paths.events))
        .expect("events file should be readable")
        .lines()
        .count();
    assert_eq!(event_line_count, outcome.traces.len());

    let trace_line_count =
        fs::read_to_string(output_dir.join(&manifest.artifact_paths.ts_resolution_trace))
            .expect("trace file should be readable")
            .lines()
            .count();
    assert_eq!(trace_line_count, outcome.traces.len());

    let drift_json = fs::read_to_string(output_dir.join(&manifest.artifact_paths.drift_report))
        .expect("drift report should be readable");
    assert!(drift_json.contains("candidate_order_mismatch"));

    let _ = fs::remove_dir_all(&output_dir);
}

// ─── Section 3: Error Paths ──────────────────────────────────────────

#[test]
fn resolve_empty_specifier_returns_empty_specifier_error() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("", TsRequestStyle::Import);
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
    assert_eq!(err.code.stable_code(), "FE-TSRES-0001");
    assert!(!err.traces.is_empty());
    assert!(err.traces.iter().any(|t| t.event == "validate_specifier"));
}

#[test]
fn resolve_whitespace_only_specifier_returns_empty_specifier_error() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("   ", TsRequestStyle::Import);
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
}

#[test]
fn resolve_relative_without_referrer_returns_missing_referrer_error() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("./utils", TsRequestStyle::Import);
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::MissingReferrer);
    assert_eq!(err.code.stable_code(), "FE-TSRES-0002");
    assert!(err.traces.iter().any(|t| t.event == "resolve_relative"));
}

#[test]
fn resolve_relative_with_builtin_referrer_returns_invalid_referrer_error() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request =
        TsModuleRequest::new("./utils", TsRequestStyle::Import).with_referrer("builtin:node:fs");
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
    assert_eq!(err.code.stable_code(), "FE-TSRES-0003");
}

#[test]
fn resolve_relative_with_external_referrer_returns_invalid_referrer_error() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("./utils", TsRequestStyle::Import)
        .with_referrer("external:some-module");
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn resolve_relative_with_empty_referrer_returns_invalid_referrer_error() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("./utils", TsRequestStyle::Import).with_referrer("");
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::InvalidReferrer);
}

#[test]
fn resolve_nonexistent_module_returns_module_not_found() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("nonexistent-package", TsRequestStyle::Import);
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::ModuleNotFound);
    assert_eq!(err.code.stable_code(), "FE-TSRES-0005");
    assert!(err.traces.iter().any(|t| t.event == "module_not_found"));
}

#[test]
fn resolve_package_with_no_matching_export_returns_package_resolution_failed() {
    let mut config = base_config();
    config.import_conditions = vec!["import".to_string()];
    config.import_extensions = vec![".js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);

    let package = TsPackageDefinition::new("mypkg", "/repo/node_modules/mypkg").with_export(
        ".",
        TsPackageExportTarget {
            condition_targets: BTreeMap::new(),
            fallback_target: None,
        },
    );
    resolver.register_package(package);

    let request = TsModuleRequest::new("mypkg", TsRequestStyle::Import);
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::PackageResolutionFailed);
    assert_eq!(err.code.stable_code(), "FE-TSRES-0004");
}

#[test]
fn error_display_format_contains_stable_code_and_message() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::ModuleNotFound,
        message: "unable to resolve 'foo'".to_string(),
        traces: vec![],
    };
    let display = format!("{err}");
    assert!(display.contains("FE-TSRES-0005"));
    assert!(display.contains("unable to resolve 'foo'"));
}

#[test]
fn error_serde_roundtrip_preserves_all_fields() {
    let err = TsModuleResolutionError {
        code: TsResolutionErrorCode::PackageResolutionFailed,
        message: "no export for ./deep".to_string(),
        traces: vec![TsResolutionTraceEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "ts_module_resolver".to_string(),
            event: "package_resolution".to_string(),
            outcome: "deny".to_string(),
            error_code: "FE-TSRES-0004".to_string(),
            detail: "no matching export".to_string(),
            candidate: Some("./deep".to_string()),
        }],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TsModuleResolutionError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
    assert_eq!(back.traces.len(), 1);
    assert_eq!(back.traces[0].candidate.as_deref(), Some("./deep"));
}

// ─── Section 4: Resolver Mode Variants ───────────────────────────────

#[test]
fn resolver_node16_mode_uses_default_extensions() {
    let config = TsModuleResolutionConfig {
        project_root: "/repo".to_string(),
        base_url: ".".to_string(),
        mode: TsModuleResolutionMode::Node16,
        import_extensions: vec![".ts".to_string()],
        ..TsModuleResolutionConfig::default()
    };
    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/util.ts");

    let request = TsModuleRequest::new("lib/util", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("should resolve");
    assert_eq!(outcome.resolved_path, "/repo/lib/util.ts");
}

#[test]
fn resolver_bundler_mode_uses_default_extensions() {
    let config = TsModuleResolutionConfig {
        project_root: "/repo".to_string(),
        base_url: ".".to_string(),
        mode: TsModuleResolutionMode::Bundler,
        import_extensions: vec![".tsx".to_string()],
        ..TsModuleResolutionConfig::default()
    };
    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/components/App.tsx");

    let request = TsModuleRequest::new("components/App", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("should resolve");
    assert_eq!(outcome.resolved_path, "/repo/components/App.tsx");
}

// ─── Section 5: Relative Resolution ─────────────────────────────────

#[test]
fn resolve_relative_import_with_referrer() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/utils/math.ts");

    let request = TsModuleRequest::new("./utils/math", TsRequestStyle::Import)
        .with_referrer("/repo/src/index.ts");
    let outcome = resolver
        .resolve(&request, &context())
        .expect("should resolve relative");
    assert_eq!(outcome.resolved_path, "/repo/src/utils/math.ts");
    assert_eq!(outcome.style, TsRequestStyle::Import);
}

#[test]
fn resolve_parent_relative_import() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/shared/types.ts");

    let request = TsModuleRequest::new("../shared/types", TsRequestStyle::Import)
        .with_referrer("/repo/src/lib/index.ts");
    let outcome = resolver
        .resolve(&request, &context())
        .expect("should resolve parent-relative");
    assert_eq!(outcome.resolved_path, "/repo/src/shared/types.ts");
}

#[test]
fn resolve_absolute_specifier() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/vendor/lib.ts");

    let request = TsModuleRequest::new("/repo/vendor/lib", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("absolute should resolve");
    assert_eq!(outcome.resolved_path, "/repo/vendor/lib.ts");
}

// ─── Section 6: Package Exports ──────────────────────────────────────

#[test]
fn package_fallback_target_used_when_no_condition_matches() {
    let mut config = base_config();
    config.import_conditions = vec!["browser".to_string()];
    config.import_extensions = vec![".js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/node_modules/lib/dist/index.js");

    let mut condition_targets = BTreeMap::new();
    condition_targets.insert("node".to_string(), "./node/index".to_string());

    let package = TsPackageDefinition::new("lib", "/repo/node_modules/lib").with_export(
        ".",
        TsPackageExportTarget {
            condition_targets,
            fallback_target: Some("./dist/index".to_string()),
        },
    );
    resolver.register_package(package);

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("lib", TsRequestStyle::Import),
            &context(),
        )
        .expect("fallback should resolve");
    assert_eq!(
        outcome.resolved_path,
        "/repo/node_modules/lib/dist/index.js"
    );
    assert_eq!(outcome.selected_condition.as_deref(), Some("fallback"));
    assert_eq!(outcome.package_name.as_deref(), Some("lib"));
}

#[test]
fn package_scoped_name_resolves_correctly() {
    let mut config = base_config();
    config.import_conditions = vec!["import".to_string()];
    config.import_extensions = vec![".mjs".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/node_modules/@acme/utils/dist/index.mjs");

    let mut condition_targets = BTreeMap::new();
    condition_targets.insert("import".to_string(), "./dist/index".to_string());

    let package = TsPackageDefinition::new("@acme/utils", "/repo/node_modules/@acme/utils")
        .with_export(
            ".",
            TsPackageExportTarget {
                condition_targets,
                fallback_target: None,
            },
        );
    resolver.register_package(package);

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("@acme/utils", TsRequestStyle::Import),
            &context(),
        )
        .expect("scoped package should resolve");
    assert_eq!(
        outcome.resolved_path,
        "/repo/node_modules/@acme/utils/dist/index.mjs"
    );
    assert_eq!(outcome.package_name.as_deref(), Some("@acme/utils"));
}

#[test]
fn package_wildcard_export_resolves_subpath() {
    let mut config = base_config();
    config.import_conditions = vec!["import".to_string()];
    config.import_extensions = vec![".js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/node_modules/toolkit/lib/helpers.js");

    let mut condition_targets = BTreeMap::new();
    condition_targets.insert("import".to_string(), "./lib/*".to_string());

    let package = TsPackageDefinition::new("toolkit", "/repo/node_modules/toolkit").with_export(
        "./*",
        TsPackageExportTarget {
            condition_targets,
            fallback_target: None,
        },
    );
    resolver.register_package(package);

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("toolkit/helpers", TsRequestStyle::Import),
            &context(),
        )
        .expect("wildcard export should resolve");
    assert_eq!(
        outcome.resolved_path,
        "/repo/node_modules/toolkit/lib/helpers.js"
    );
}

#[test]
fn package_with_multiple_export_entries() {
    let mut config = base_config();
    config.import_conditions = vec!["import".to_string()];
    config.import_extensions = vec![".mjs".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/node_modules/multi/dist/main.mjs");
    resolver.register_file("/repo/node_modules/multi/dist/utils.mjs");

    let mut main_conditions = BTreeMap::new();
    main_conditions.insert("import".to_string(), "./dist/main".to_string());
    let mut utils_conditions = BTreeMap::new();
    utils_conditions.insert("import".to_string(), "./dist/utils".to_string());

    let package = TsPackageDefinition::new("multi", "/repo/node_modules/multi")
        .with_export(
            ".",
            TsPackageExportTarget {
                condition_targets: main_conditions,
                fallback_target: None,
            },
        )
        .with_export(
            "./utils",
            TsPackageExportTarget {
                condition_targets: utils_conditions,
                fallback_target: None,
            },
        );
    resolver.register_package(package);

    let main_outcome = resolver
        .resolve(
            &TsModuleRequest::new("multi", TsRequestStyle::Import),
            &context(),
        )
        .expect("main entry should resolve");
    assert_eq!(
        main_outcome.resolved_path,
        "/repo/node_modules/multi/dist/main.mjs"
    );

    let utils_outcome = resolver
        .resolve(
            &TsModuleRequest::new("multi/utils", TsRequestStyle::Import),
            &context(),
        )
        .expect("utils entry should resolve");
    assert_eq!(
        utils_outcome.resolved_path,
        "/repo/node_modules/multi/dist/utils.mjs"
    );
}

// ─── Section 7: Multiple Paths Alias Entries ─────────────────────────

#[test]
fn multiple_paths_alias_entries_with_specificity_ordering() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];
    config.paths = BTreeMap::from([
        ("@lib/*".to_string(), vec!["packages/lib/*".to_string()]),
        (
            "@lib/core/*".to_string(),
            vec!["packages/lib/core-v2/*".to_string()],
        ),
    ]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/lib/core-v2/math.ts");
    resolver.register_file("/repo/packages/lib/core/math.ts");

    let request = TsModuleRequest::new("@lib/core/math", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("more-specific alias should win");
    assert_eq!(outcome.resolved_path, "/repo/packages/lib/core-v2/math.ts");
}

#[test]
fn paths_alias_with_multiple_replacement_targets() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];
    config.paths = BTreeMap::from([(
        "@shared/*".to_string(),
        vec![
            "packages/shared-v2/src/*".to_string(),
            "packages/shared/src/*".to_string(),
        ],
    )]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    // Only second replacement target has the file
    resolver.register_file("/repo/packages/shared/src/logger.ts");

    let request = TsModuleRequest::new("@shared/logger", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("second replacement target should resolve");
    assert_eq!(outcome.resolved_path, "/repo/packages/shared/src/logger.ts");
}

// ─── Section 8: Base URL Fallback ────────────────────────────────────

#[test]
fn base_url_fallback_resolves_bare_specifier_when_no_alias_matches() {
    let mut config = base_config();
    config.base_url = "src".to_string();
    config.import_extensions = vec![".ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/components/Button.ts");

    let request = TsModuleRequest::new("components/Button", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("baseUrl fallback should resolve bare specifier");
    assert_eq!(outcome.resolved_path, "/repo/src/components/Button.ts");

    assert!(
        outcome
            .traces
            .iter()
            .any(|t| t.event == "base_url_fallback"),
        "expected base_url_fallback trace event"
    );
}

#[test]
fn base_url_dot_resolves_relative_to_project_root() {
    let mut config = base_config();
    config.base_url = ".".to_string();
    config.import_extensions = vec![".ts".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/helpers.ts");

    let request = TsModuleRequest::new("lib/helpers", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("dot baseUrl should resolve from project root");
    assert_eq!(outcome.resolved_path, "/repo/lib/helpers.ts");
}

#[test]
fn base_url_absolute_path() {
    let config = TsModuleResolutionConfig {
        project_root: "/repo".to_string(),
        base_url: "/custom/base".to_string(),
        mode: TsModuleResolutionMode::NodeNext,
        import_extensions: vec![".ts".to_string()],
        ..TsModuleResolutionConfig::default()
    };
    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/custom/base/tools/cli.ts");

    let request = TsModuleRequest::new("tools/cli", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("absolute baseUrl should resolve");
    assert_eq!(outcome.resolved_path, "/custom/base/tools/cli.ts");
}

// ─── Section 9: Index File Resolution ────────────────────────────────

#[test]
fn index_file_resolution_for_directory_import() {
    let mut config = base_config();
    config.import_extensions = vec!["/index.ts".to_string(), "/index.js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/models/index.ts");

    let request =
        TsModuleRequest::new("./src/models", TsRequestStyle::Import).with_referrer("/repo/main.ts");
    let outcome = resolver
        .resolve(&request, &context())
        .expect("index.ts should be found");
    assert_eq!(outcome.resolved_path, "/repo/src/models/index.ts");
}

#[test]
fn index_js_fallback_when_index_ts_missing() {
    let mut config = base_config();
    config.import_extensions = vec![
        ".ts".to_string(),
        "/index.ts".to_string(),
        "/index.js".to_string(),
    ];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/legacy/index.js");

    let request =
        TsModuleRequest::new("./src/legacy", TsRequestStyle::Import).with_referrer("/repo/main.ts");
    let outcome = resolver
        .resolve(&request, &context())
        .expect("index.js fallback should work");
    assert_eq!(outcome.resolved_path, "/repo/src/legacy/index.js");
}

// ─── Section 10: Require vs Import Extension Handling ────────────────

#[test]
fn require_style_uses_cts_and_cjs_extensions() {
    let mut config = base_config();
    config.require_extensions = vec![".cts".to_string(), ".cjs".to_string(), ".js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/config.cts");

    let request = TsModuleRequest::new("lib/config", TsRequestStyle::Require);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("require should resolve .cts");
    assert_eq!(outcome.resolved_path, "/repo/lib/config.cts");
    assert_eq!(outcome.style, TsRequestStyle::Require);
}

#[test]
fn import_style_prefers_mts_over_js() {
    let mut config = base_config();
    config.import_extensions = vec![".mts".to_string(), ".js".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/util.mts");
    resolver.register_file("/repo/lib/util.js");

    let request = TsModuleRequest::new("lib/util", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("import should prefer .mts");
    assert_eq!(outcome.resolved_path, "/repo/lib/util.mts");
}

// ─── Section 11: Serde Roundtrips ────────────────────────────────────

#[test]
fn resolution_mode_serde_roundtrip_all_variants() {
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
fn request_style_serde_roundtrip_all_variants() {
    for style in [TsRequestStyle::Import, TsRequestStyle::Require] {
        let json = serde_json::to_string(&style).unwrap();
        let back: TsRequestStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(style, back);
    }
}

#[test]
fn drift_class_serde_roundtrip_all_variants() {
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
fn error_code_serde_roundtrip_all_variants() {
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
fn trace_event_serde_roundtrip() {
    let event = TsResolutionTraceEvent {
        trace_id: "t-123".to_string(),
        decision_id: "d-456".to_string(),
        policy_id: "p-789".to_string(),
        component: "ts_module_resolver".to_string(),
        event: "extension_probe".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
        detail: "resolved from alias".to_string(),
        candidate: Some("/repo/src/math.ts".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: TsResolutionTraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn trace_event_serde_with_none_candidate() {
    let event = TsResolutionTraceEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "ts_module_resolver".to_string(),
        event: "validate_specifier".to_string(),
        outcome: "deny".to_string(),
        error_code: "FE-TSRES-0001".to_string(),
        detail: "empty".to_string(),
        candidate: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: TsResolutionTraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.candidate, None);
}

#[test]
fn outcome_serde_roundtrip() {
    let outcome = TsModuleResolutionOutcome {
        request_specifier: "@core/math".to_string(),
        resolved_path: "/repo/packages/core/src/math.ts".to_string(),
        style: TsRequestStyle::Import,
        package_name: None,
        selected_condition: None,
        traces: vec![],
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: TsModuleResolutionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

#[test]
fn config_serde_roundtrip_with_paths() {
    let mut config = base_config();
    config.paths = BTreeMap::from([
        ("@app/*".to_string(), vec!["src/*".to_string()]),
        ("@lib/*".to_string(), vec!["lib/*".to_string()]),
    ]);
    let json = serde_json::to_string(&config).unwrap();
    let back: TsModuleResolutionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn package_definition_serde_roundtrip() {
    let mut condition_targets = BTreeMap::new();
    condition_targets.insert("import".to_string(), "./esm/index".to_string());
    condition_targets.insert("require".to_string(), "./cjs/index".to_string());

    let package = TsPackageDefinition::new("toolkit", "/nm/toolkit").with_export(
        ".",
        TsPackageExportTarget {
            condition_targets,
            fallback_target: Some("./dist/index".to_string()),
        },
    );
    let json = serde_json::to_string(&package).unwrap();
    let back: TsPackageDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(package, back);
}

#[test]
fn artifact_paths_serde_roundtrip() {
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
fn run_manifest_serde_roundtrip() {
    let manifest = TsResolutionRunManifest {
        schema_version: SCHEMA_VERSION.to_string(),
        scenario_id: "test-scenario".to_string(),
        generated_at_utc: "2026-03-04T00:00:00Z".to_string(),
        trace_count: 5,
        drift_class: TsResolutionDriftClass::NoDrift,
        artifact_paths: TsResolutionArtifactPaths {
            run_manifest: "run_manifest.json".to_string(),
            events: "events.jsonl".to_string(),
            commands: "commands.txt".to_string(),
            ts_resolution_trace: "ts_resolution_trace.jsonl".to_string(),
            drift_report: "drift_report.json".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TsResolutionRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ─── Section 12: Drift Classification ────────────────────────────────

#[test]
fn drift_no_drift_when_candidates_match() {
    let candidates = vec!["a.ts".to_string(), "b.ts".to_string()];
    let drift = classify_resolution_drift(&candidates, &candidates);
    assert_eq!(drift.class, TsResolutionDriftClass::NoDrift);
    assert!(!drift.drift_detected);
}

#[test]
fn drift_candidate_order_mismatch_detected() {
    let reference = vec!["a.ts".to_string(), "b.ts".to_string()];
    let observed = vec!["b.ts".to_string(), "a.ts".to_string()];
    let drift = classify_resolution_drift(&reference, &observed);
    assert_eq!(drift.class, TsResolutionDriftClass::CandidateOrderMismatch);
    assert!(drift.drift_detected);
    assert!(drift.remediation.contains("ordering"));
}

#[test]
fn drift_missing_target_detected() {
    let reference = vec!["a.ts".to_string(), "b.ts".to_string(), "c.ts".to_string()];
    let observed = vec!["a.ts".to_string(), "c.ts".to_string()];
    let drift = classify_resolution_drift(&reference, &observed);
    assert_eq!(drift.class, TsResolutionDriftClass::MissingTarget);
    assert!(drift.drift_detected);
}

#[test]
fn drift_extra_target_detected() {
    let reference = vec!["a.ts".to_string()];
    let observed = vec!["a.ts".to_string(), "b.ts".to_string()];
    let drift = classify_resolution_drift(&reference, &observed);
    assert_eq!(drift.class, TsResolutionDriftClass::ExtraTarget);
    assert!(drift.drift_detected);
}

#[test]
fn drift_full_mismatch_detected() {
    let reference = vec!["a.ts".to_string(), "b.ts".to_string()];
    let observed = vec!["c.ts".to_string(), "d.ts".to_string()];
    let drift = classify_resolution_drift(&reference, &observed);
    assert_eq!(drift.class, TsResolutionDriftClass::FullMismatch);
    assert!(drift.drift_detected);
}

#[test]
fn drift_empty_candidates_is_no_drift() {
    let drift = classify_resolution_drift(&[], &[]);
    assert_eq!(drift.class, TsResolutionDriftClass::NoDrift);
    assert!(!drift.drift_detected);
}

#[test]
fn drift_report_serde_roundtrip() {
    let report = TsResolutionDriftReport {
        drift_detected: true,
        class: TsResolutionDriftClass::MissingTarget,
        reference_candidates: vec!["a.ts".to_string(), "b.ts".to_string()],
        observed_candidates: vec!["a.ts".to_string()],
        remediation: "Add missing targets".to_string(),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: TsResolutionDriftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn drift_remediation_text_is_nonempty_for_all_classes() {
    let cases: Vec<(Vec<String>, Vec<String>, TsResolutionDriftClass)> = vec![
        (
            vec!["a".into()],
            vec!["a".into()],
            TsResolutionDriftClass::NoDrift,
        ),
        (
            vec!["a".into(), "b".into()],
            vec!["b".into(), "a".into()],
            TsResolutionDriftClass::CandidateOrderMismatch,
        ),
        (
            vec!["a".into(), "b".into()],
            vec!["a".into()],
            TsResolutionDriftClass::MissingTarget,
        ),
        (
            vec!["a".into()],
            vec!["a".into(), "b".into()],
            TsResolutionDriftClass::ExtraTarget,
        ),
        (
            vec!["a".into()],
            vec!["b".into()],
            TsResolutionDriftClass::FullMismatch,
        ),
    ];
    for (reference, observed, expected_class) in cases {
        let drift = classify_resolution_drift(&reference, &observed);
        assert_eq!(drift.class, expected_class);
        assert!(
            !drift.remediation.trim().is_empty(),
            "empty remediation for {expected_class:?}"
        );
    }
}

// ─── Section 13: Artifact Emission ───────────────────────────────────

#[test]
fn artifact_writer_creates_all_required_files() {
    let output_dir = unique_temp_dir("artifact_all_files");
    fs::create_dir_all(&output_dir).expect("create dir");

    let traces = vec![TsResolutionTraceEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "ts_module_resolver".to_string(),
        event: "extension_probe".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
        detail: "test".to_string(),
        candidate: Some("/test/file.ts".to_string()),
    }];

    let drift = classify_resolution_drift(&["a.ts".to_string()], &["a.ts".to_string()]);

    let commands = vec!["echo test".to_string()];

    let manifest = write_ts_resolution_artifacts(
        &output_dir,
        "test-scenario",
        "2026-03-04T12:00:00Z",
        &commands,
        &traces,
        &drift,
    )
    .expect("writer should succeed");

    assert!(
        output_dir
            .join(&manifest.artifact_paths.run_manifest)
            .exists()
    );
    assert!(output_dir.join(&manifest.artifact_paths.events).exists());
    assert!(output_dir.join(&manifest.artifact_paths.commands).exists());
    assert!(
        output_dir
            .join(&manifest.artifact_paths.ts_resolution_trace)
            .exists()
    );
    assert!(
        output_dir
            .join(&manifest.artifact_paths.drift_report)
            .exists()
    );

    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    assert_eq!(manifest.scenario_id, "test-scenario");
    assert_eq!(manifest.trace_count, 1);
    assert_eq!(manifest.drift_class, TsResolutionDriftClass::NoDrift);

    let _ = fs::remove_dir_all(&output_dir);
}

#[test]
fn artifact_writer_events_jsonl_is_valid_json_per_line() {
    let output_dir = unique_temp_dir("artifact_jsonl");
    fs::create_dir_all(&output_dir).expect("create dir");

    let traces = vec![
        TsResolutionTraceEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "ts_module_resolver".to_string(),
            event: "extension_probe".to_string(),
            outcome: "allow".to_string(),
            error_code: "none".to_string(),
            detail: "first".to_string(),
            candidate: Some("/a.ts".to_string()),
        },
        TsResolutionTraceEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "ts_module_resolver".to_string(),
            event: "module_not_found".to_string(),
            outcome: "deny".to_string(),
            error_code: "FE-TSRES-0005".to_string(),
            detail: "second".to_string(),
            candidate: None,
        },
    ];

    let drift = classify_resolution_drift(&[], &[]);
    let manifest = write_ts_resolution_artifacts(
        &output_dir,
        "jsonl-test",
        "2026-03-04T12:00:00Z",
        &[],
        &traces,
        &drift,
    )
    .expect("writer");

    let events_content =
        fs::read_to_string(output_dir.join(&manifest.artifact_paths.events)).expect("read events");
    let lines: Vec<&str> = events_content.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let _: Value = serde_json::from_str(line).expect("each line should be valid JSON");
    }

    let trace_content =
        fs::read_to_string(output_dir.join(&manifest.artifact_paths.ts_resolution_trace))
            .expect("read traces");
    let trace_lines: Vec<&str> = trace_content.lines().collect();
    assert_eq!(trace_lines.len(), 2);
    for line in &trace_lines {
        let parsed: TsResolutionTraceEvent =
            serde_json::from_str(line).expect("trace line should deserialize");
        assert_eq!(parsed.component, "ts_module_resolver");
    }

    let _ = fs::remove_dir_all(&output_dir);
}

#[test]
fn artifact_writer_manifest_is_valid_json() {
    let output_dir = unique_temp_dir("artifact_manifest");
    fs::create_dir_all(&output_dir).expect("create dir");

    let drift = classify_resolution_drift(&[], &[]);
    let manifest = write_ts_resolution_artifacts(
        &output_dir,
        "manifest-test",
        "2026-03-04T12:00:00Z",
        &["cmd1".to_string(), "cmd2".to_string()],
        &[],
        &drift,
    )
    .expect("writer");

    let manifest_content =
        fs::read_to_string(output_dir.join(&manifest.artifact_paths.run_manifest))
            .expect("read manifest");
    let parsed: TsResolutionRunManifest =
        serde_json::from_str(&manifest_content).expect("manifest should be valid JSON");
    assert_eq!(parsed.schema_version, SCHEMA_VERSION);
    assert_eq!(parsed.scenario_id, "manifest-test");
    assert_eq!(parsed.trace_count, 0);

    let _ = fs::remove_dir_all(&output_dir);
}

#[test]
fn artifact_writer_drift_report_is_valid_json() {
    let output_dir = unique_temp_dir("artifact_drift");
    fs::create_dir_all(&output_dir).expect("create dir");

    let drift = classify_resolution_drift(
        &["a.ts".to_string(), "b.ts".to_string()],
        &["b.ts".to_string(), "a.ts".to_string()],
    );
    let manifest = write_ts_resolution_artifacts(
        &output_dir,
        "drift-test",
        "2026-03-04T12:00:00Z",
        &[],
        &[],
        &drift,
    )
    .expect("writer");

    let drift_content = fs::read_to_string(output_dir.join(&manifest.artifact_paths.drift_report))
        .expect("read drift");
    let parsed: TsResolutionDriftReport =
        serde_json::from_str(&drift_content).expect("drift report should be valid JSON");
    assert_eq!(parsed.class, TsResolutionDriftClass::CandidateOrderMismatch);
    assert!(parsed.drift_detected);

    let _ = fs::remove_dir_all(&output_dir);
}

// ─── Section 14: Trace Event Behavior ────────────────────────────────

#[test]
fn all_traces_have_correct_context_fields() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];
    config.paths = BTreeMap::from([("@app/*".to_string(), vec!["src/*".to_string()])]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/index.ts");

    let ctx = TsResolutionContext::new("trace-ctx-1", "decision-ctx-1", "policy-ctx-1");
    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("@app/index", TsRequestStyle::Import),
            &ctx,
        )
        .expect("should resolve");

    for trace in &outcome.traces {
        assert_eq!(trace.trace_id, "trace-ctx-1");
        assert_eq!(trace.decision_id, "decision-ctx-1");
        assert_eq!(trace.policy_id, "policy-ctx-1");
        assert_eq!(trace.component, "ts_module_resolver");
    }
}

#[test]
fn error_traces_have_correct_context_fields() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let ctx = TsResolutionContext::new("t-err", "d-err", "p-err");
    let err = resolver
        .resolve(&TsModuleRequest::new("", TsRequestStyle::Import), &ctx)
        .unwrap_err();

    for trace in &err.traces {
        assert_eq!(trace.trace_id, "t-err");
        assert_eq!(trace.decision_id, "d-err");
        assert_eq!(trace.policy_id, "p-err");
    }
}

#[test]
fn probe_sequence_extracts_only_extension_probe_candidates() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string(), ".js".to_string()];
    config.paths = BTreeMap::from([("@lib/*".to_string(), vec!["lib/*".to_string()])]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/util.js");

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("@lib/util", TsRequestStyle::Import),
            &context(),
        )
        .expect("should resolve");

    let probes = outcome.probe_sequence();
    assert!(probes.len() >= 2, "should have probed multiple candidates");
    // The successful probe should be in the sequence
    assert!(
        probes.contains(&"/repo/lib/util.js".to_string()),
        "successful candidate should be in probe sequence"
    );
}

// ─── Section 15: Edge Cases ──────────────────────────────────────────

#[test]
fn resolver_handles_empty_extensions_list_with_defaults() {
    let config = TsModuleResolutionConfig {
        project_root: "/repo".to_string(),
        base_url: ".".to_string(),
        mode: TsModuleResolutionMode::NodeNext,
        import_extensions: vec![],
        ..TsModuleResolutionConfig::default()
    };
    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/util.ts");

    let request = TsModuleRequest::new("lib/util", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("default extensions should work");
    assert_eq!(outcome.resolved_path, "/repo/lib/util.ts");
}

#[test]
fn resolver_normalizes_project_root_path() {
    let config = TsModuleResolutionConfig {
        project_root: "/repo/./sub/../".to_string(),
        base_url: ".".to_string(),
        mode: TsModuleResolutionMode::NodeNext,
        import_extensions: vec![".ts".to_string()],
        ..TsModuleResolutionConfig::default()
    };
    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/util.ts");

    let request = TsModuleRequest::new("lib/util", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("normalized root should work");
    assert_eq!(outcome.resolved_path, "/repo/lib/util.ts");
}

#[test]
fn resolver_handles_empty_base_url() {
    let config = TsModuleResolutionConfig {
        project_root: "/repo".to_string(),
        base_url: "".to_string(),
        mode: TsModuleResolutionMode::NodeNext,
        import_extensions: vec![".ts".to_string()],
        ..TsModuleResolutionConfig::default()
    };
    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/main.ts");

    let request = TsModuleRequest::new("src/main", TsRequestStyle::Import);
    let outcome = resolver
        .resolve(&request, &context())
        .expect("empty base_url should default to dot");
    assert_eq!(outcome.resolved_path, "/repo/src/main.ts");
}

#[test]
fn resolver_deduplicates_probe_candidates() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];
    config.paths = BTreeMap::from([("@lib/*".to_string(), vec!["lib/*".to_string()])]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/lib/util.ts");

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("@lib/util", TsRequestStyle::Import),
            &context(),
        )
        .expect("should resolve");

    let probes = outcome.probe_sequence();
    let unique_probes: BTreeSet<&String> = probes.iter().collect();
    assert_eq!(
        probes.len(),
        unique_probes.len(),
        "probe sequence should not have duplicates"
    );
}

#[test]
fn resolver_with_no_files_returns_module_not_found() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("anything", TsRequestStyle::Import);
    let err = resolver.resolve(&request, &context()).unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::ModuleNotFound);
}

// ─── Section 16: Determinism Guarantees ──────────────────────────────

#[test]
fn deterministic_resolution_across_multiple_invocations() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string(), ".js".to_string()];
    config.paths = BTreeMap::from([("@app/*".to_string(), vec!["src/*".to_string()])]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/src/main.ts");
    resolver.register_file("/repo/src/main.js");

    let request = TsModuleRequest::new("@app/main", TsRequestStyle::Import);

    let results: Vec<_> = (0..10)
        .map(|_| {
            resolver
                .resolve(&request, &context())
                .expect("should resolve")
        })
        .collect();

    for result in &results {
        assert_eq!(result.resolved_path, results[0].resolved_path);
        assert_eq!(result.traces, results[0].traces);
    }
}

#[test]
fn deterministic_error_traces_across_invocations() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let request = TsModuleRequest::new("nonexistent", TsRequestStyle::Import);

    let errors: Vec<_> = (0..5)
        .map(|_| resolver.resolve(&request, &context()).unwrap_err())
        .collect();

    for err in &errors {
        assert_eq!(err.code, errors[0].code);
        assert_eq!(err.message, errors[0].message);
        assert_eq!(err.traces, errors[0].traces);
    }
}

#[test]
fn file_registration_order_does_not_affect_resolution() {
    let make_resolver = |order: &[&str]| {
        let mut config = base_config();
        config.import_extensions = vec![".ts".to_string()];
        let mut resolver = DeterministicTsModuleResolver::new(config);
        for file in order {
            resolver.register_file(*file);
        }
        resolver
    };

    let resolver_a = make_resolver(&["/repo/src/a.ts", "/repo/src/b.ts", "/repo/src/c.ts"]);
    let resolver_b = make_resolver(&["/repo/src/c.ts", "/repo/src/a.ts", "/repo/src/b.ts"]);

    let request = TsModuleRequest::new("src/a", TsRequestStyle::Import);
    let outcome_a = resolver_a.resolve(&request, &context()).expect("a");
    let outcome_b = resolver_b.resolve(&request, &context()).expect("b");

    assert_eq!(outcome_a.resolved_path, outcome_b.resolved_path);
}

// ─── Section 17: Context and Module Request Construction ─────────────

#[test]
fn context_fields_are_preserved() {
    let ctx = TsResolutionContext::new("t-custom", "d-custom", "p-custom");
    assert_eq!(ctx.trace_id, "t-custom");
    assert_eq!(ctx.decision_id, "d-custom");
    assert_eq!(ctx.policy_id, "p-custom");
}

#[test]
fn module_request_with_referrer_chain() {
    let req = TsModuleRequest::new("./foo", TsRequestStyle::Import).with_referrer("/first/ref.ts");
    assert_eq!(req.referrer.as_deref(), Some("/first/ref.ts"));

    let req2 = req.with_referrer("/second/ref.ts");
    assert_eq!(req2.referrer.as_deref(), Some("/second/ref.ts"));
}

#[test]
fn package_definition_builder_pattern() {
    let mut cond_a = BTreeMap::new();
    cond_a.insert("import".to_string(), "./a".to_string());
    let mut cond_b = BTreeMap::new();
    cond_b.insert("import".to_string(), "./b".to_string());

    let pkg = TsPackageDefinition::new("multi", "/nm/multi")
        .with_export(
            ".",
            TsPackageExportTarget {
                condition_targets: cond_a,
                fallback_target: None,
            },
        )
        .with_export(
            "./sub",
            TsPackageExportTarget {
                condition_targets: cond_b,
                fallback_target: None,
            },
        );
    assert_eq!(pkg.exports.len(), 2);
    assert!(pkg.exports.contains_key("."));
    assert!(pkg.exports.contains_key("./sub"));
}

// ─── Section 18: Outcome Fields ──────────────────────────────────────

#[test]
fn outcome_fields_populated_for_alias_resolution() {
    let mut config = base_config();
    config.import_extensions = vec![".ts".to_string()];
    config.paths = BTreeMap::from([("@core/*".to_string(), vec!["packages/core/*".to_string()])]);

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/packages/core/util.ts");

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("@core/util", TsRequestStyle::Import),
            &context(),
        )
        .expect("should resolve");

    assert_eq!(outcome.request_specifier, "@core/util");
    assert_eq!(outcome.resolved_path, "/repo/packages/core/util.ts");
    assert_eq!(outcome.style, TsRequestStyle::Import);
    assert!(outcome.package_name.is_none());
    assert!(outcome.selected_condition.is_none());
    assert!(!outcome.traces.is_empty());
}

#[test]
fn outcome_fields_populated_for_package_resolution() {
    let mut config = base_config();
    config.import_conditions = vec!["import".to_string()];
    config.import_extensions = vec![".mjs".to_string()];

    let mut resolver = DeterministicTsModuleResolver::new(config);
    resolver.register_file("/repo/node_modules/react/esm/index.mjs");

    let mut conditions = BTreeMap::new();
    conditions.insert("import".to_string(), "./esm/index".to_string());

    resolver.register_package(
        TsPackageDefinition::new("react", "/repo/node_modules/react").with_export(
            ".",
            TsPackageExportTarget {
                condition_targets: conditions,
                fallback_target: None,
            },
        ),
    );

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("react", TsRequestStyle::Import),
            &context(),
        )
        .expect("should resolve");

    assert_eq!(outcome.request_specifier, "react");
    assert_eq!(outcome.package_name.as_deref(), Some("react"));
    assert_eq!(outcome.selected_condition.as_deref(), Some("import"));
}
