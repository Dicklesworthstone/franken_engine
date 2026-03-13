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
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ts_module_resolution::{
    DeterministicTsModuleResolver, TsModuleRequest, TsModuleResolutionConfig,
    TsModuleResolutionMode, TsPackageDefinition, TsPackageExportTarget, TsRequestStyle,
    TsResolutionContext, TsResolutionErrorCode, TsResolutionIndexBuildPolicy,
    TsResolutionIndexFallbackReason, TsResolutionIndexStepLog, TsResolutionTraceEvent,
    write_ts_resolution_index_artifacts,
};
use serde_json::Value;

const SCHEMA_VERSION: &str = "rgc.ts-module-resolution.index.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_module_resolution_index_v1.json");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn context() -> TsResolutionContext {
    TsResolutionContext::new(
        "trace-tsres-index-1",
        "decision-tsres-index-1",
        "policy-tsres-index-1",
    )
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
    repo_root()
        .join("artifacts")
        .join("rgc_module_resolution_index")
        .join("_tmp")
        .join(format!(
            "frx_module_resolution_index_{label}_{}_{}",
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

fn export_target(condition: &str, path: &str) -> TsPackageExportTarget {
    TsPackageExportTarget {
        condition_targets: BTreeMap::from([(condition.to_string(), path.to_string())]),
        fallback_target: None,
    }
}

fn dual_target(import_path: &str, require_path: &str) -> TsPackageExportTarget {
    TsPackageExportTarget {
        condition_targets: BTreeMap::from([
            ("import".to_string(), import_path.to_string()),
            ("require".to_string(), require_path.to_string()),
        ]),
        fallback_target: None,
    }
}

fn bridge_traces() -> Vec<TsResolutionTraceEvent> {
    vec![TsResolutionTraceEvent {
        trace_id: "trace-tsres-index-bridge".to_string(),
        decision_id: "decision-tsres-index-bridge".to_string(),
        policy_id: "policy-tsres-index-bridge".to_string(),
        component: "ts_module_resolver".to_string(),
        event: "package_index_lookup".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
        detail: "bridge artifact emission".to_string(),
        candidate: Some("/repo/node_modules/react/dist/index.mjs".to_string()),
    }]
}

fn bridge_commands() -> Vec<String> {
    std::env::var("RGC_MODULE_RESOLUTION_INDEX_COMMANDS_JSON")
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| {
            vec!["cargo test -p frankenengine-engine --test module_resolution_index".to_string()]
        })
}

fn seeded_resolver() -> DeterministicTsModuleResolver {
    let mut resolver = DeterministicTsModuleResolver::new(base_config());
    resolver.register_file("/repo/node_modules/react/dist/index.mjs");
    resolver.register_file("/repo/node_modules/react/dist/index.cjs");
    resolver.register_file("/repo/node_modules/react/dist/jsx-runtime.mjs");
    resolver.register_file("/repo/node_modules/react/dist/wild/tool.mjs");
    resolver.register_package(
        TsPackageDefinition::new("react", "/repo/node_modules/react")
            .with_export(".", dual_target("./dist/index.mjs", "./dist/index.cjs"))
            .with_export(
                "./jsx-runtime",
                export_target("import", "./dist/jsx-runtime.mjs"),
            )
            .with_export("./*", export_target("import", "./dist/wild/*.mjs")),
    );
    resolver
}

#[test]
fn rgc_406a_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_MODULE_RESOLUTION_INDEX_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required in [
        "# RGC Module Resolution Index V1",
        "## Purpose",
        "## Index Construction",
        "## Validation and Fallback",
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
fn rgc_406a_contract_schema_and_required_fields_are_present() {
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
        "bd-1lsy.5.8.1"
    );

    let index_policy = contract
        .get("index_policy")
        .expect("index_policy should exist");
    assert!(
        index_policy
            .get("deterministic")
            .and_then(Value::as_bool)
            .expect("deterministic should exist")
    );
    assert!(
        index_policy
            .get("reject_stale")
            .and_then(Value::as_bool)
            .expect("reject_stale should exist")
    );
    assert!(
        index_policy
            .get("fallback_on_unverifiable")
            .and_then(Value::as_bool)
            .expect("fallback_on_unverifiable should exist")
    );

    let index_families = contract
        .get("index_families")
        .and_then(Value::as_array)
        .expect("index_families should be array");
    assert_eq!(index_families.len(), 3);

    let artifact_contract = contract
        .get("artifact_contract")
        .expect("artifact_contract should exist");
    let required_paths = json_string_array(artifact_contract, "required_paths");
    for required in [
        "module_art_index_report.json",
        "export_map_hash_catalog.json",
        "module_index_identity_report.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "step_logs/",
    ] {
        assert!(
            required_paths.contains(&required.to_string()),
            "missing artifact path {required}"
        );
    }

    let required_artifacts = json_string_array(&contract, "required_artifacts");
    assert_eq!(
        required_artifacts, required_paths,
        "top-level required_artifacts should mirror artifact_contract.required_paths"
    );

    let gate_runner = contract
        .get("gate_runner")
        .expect("gate_runner should exist");
    assert_eq!(
        gate_runner
            .get("script")
            .and_then(Value::as_str)
            .expect("gate_runner.script should exist"),
        "scripts/run_rgc_module_resolution_index_suite.sh"
    );
    assert_eq!(
        gate_runner
            .get("replay_wrapper")
            .and_then(Value::as_str)
            .expect("gate_runner.replay_wrapper should exist"),
        "scripts/e2e/rgc_module_resolution_index_replay.sh"
    );
    assert_eq!(
        gate_runner
            .get("strict_mode")
            .and_then(Value::as_str)
            .expect("gate_runner.strict_mode should exist"),
        "ci"
    );
    assert_eq!(
        gate_runner
            .get("manifest_schema_version")
            .and_then(Value::as_str)
            .expect("gate_runner.manifest_schema_version should exist"),
        "rgc.ts-module-resolution.index.manifest.v1"
    );

    let fallback_reasons = json_string_array(&contract, "fallback_reasons");
    for required in [
        "artifact_age_exceeded",
        "workspace_fingerprint_mismatch",
        "index_fingerprint_mismatch",
        "collision_search_exhausted",
        "unsupported_wildcard_export",
    ] {
        assert!(
            fallback_reasons.contains(&required.to_string()),
            "missing fallback reason {required}"
        );
    }

    let operator_verification = json_string_array(&contract, "operator_verification").join("\n");
    assert!(operator_verification.contains("jq empty"));
    assert!(
        operator_verification.contains("./scripts/run_rgc_module_resolution_index_suite.sh ci")
    );
    assert!(
        operator_verification.contains("./scripts/e2e/rgc_module_resolution_index_replay.sh ci")
    );
    assert!(
        operator_verification
            .contains("cargo test -p frankenengine-engine --test module_resolution_index")
    );
    assert!(
        operator_verification.contains("$PWD/target_rch_module_resolution_index_verify"),
        "operator verification should use a portable repo-local rch target dir"
    );
    assert!(
        !operator_verification
            .contains("/data/projects/franken_engine/target_rch_module_resolution_index"),
        "operator verification should not hard-code a repo-specific absolute target dir"
    );
}

#[test]
fn suite_script_is_rch_backed_and_fail_closed() {
    let script =
        fs::read_to_string(repo_root().join("scripts/run_rgc_module_resolution_index_suite.sh"))
            .expect("suite script should be readable");

    assert!(script.contains("rch exec -- env"));
    assert!(script.contains("rch reported local fallback; refusing local execution"));
    assert!(script.contains("cargo check -p frankenengine-engine --test module_resolution_index"));
    assert!(script.contains("cargo test -p frankenengine-engine --test module_resolution_index"));
    assert!(
        script.contains(
            "cargo clippy -p frankenengine-engine --test module_resolution_index --no-deps -- -D warnings"
        )
    );
    assert!(script.contains("RGC_MODULE_RESOLUTION_INDEX_ARTIFACT_DIR"));
}

#[test]
fn replay_wrapper_delegates_to_suite_script() {
    let script =
        fs::read_to_string(repo_root().join("scripts/e2e/rgc_module_resolution_index_replay.sh"))
            .expect("replay wrapper should be readable");

    assert!(
        script.contains("scripts/run_rgc_module_resolution_index_suite.sh"),
        "replay wrapper should invoke the suite script"
    );
}

#[test]
fn resolution_index_bundle_is_deterministic_and_queryable() {
    let resolver = seeded_resolver();
    let first = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let second = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);

    assert_eq!(first, second);
    assert!(
        first
            .module_art_index_report
            .lookup_package("react")
            .is_some()
    );
    assert!(
        first
            .export_map_hash_catalog
            .package("react")
            .and_then(|package| package.lookup_exact_export("."))
            .is_some()
    );
    assert!(
        first
            .export_map_hash_catalog
            .package("react")
            .and_then(|package| package.lookup_hot_subpath("./jsx-runtime"))
            .is_some()
    );
}

#[test]
fn indexed_resolution_matches_incumbent_for_exact_exports_and_subpaths() {
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);

    for request in [
        TsModuleRequest::new("react", TsRequestStyle::Import),
        TsModuleRequest::new("react", TsRequestStyle::Require),
        TsModuleRequest::new("react/jsx-runtime", TsRequestStyle::Import),
    ] {
        let direct = resolver.resolve(&request, &context()).unwrap();
        let indexed = resolver
            .resolve_with_index_or_fallback(&request, &context(), &bundle, 120, 300)
            .unwrap();
        assert_eq!(direct.resolved_path, indexed.resolved_path);
        assert_eq!(direct.package_name, indexed.package_name);
        assert_eq!(direct.selected_condition, indexed.selected_condition);
    }
}

#[test]
fn wildcard_exports_fall_back_without_semantic_drift() {
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let request = TsModuleRequest::new("react/tool", TsRequestStyle::Import);
    let direct = resolver.resolve(&request, &context()).unwrap();
    let indexed = resolver
        .resolve_with_index_or_fallback(&request, &context(), &bundle, 120, 300)
        .unwrap();

    assert_eq!(direct.resolved_path, indexed.resolved_path);
    assert!(
        bundle
            .export_map_hash_catalog
            .package("react")
            .unwrap()
            .fallback_reasons
            .contains(&TsResolutionIndexFallbackReason::UnsupportedWildcardExport)
    );
}

#[test]
fn stale_and_workspace_mismatched_indexes_are_rejected_without_drift() {
    let resolver = seeded_resolver();
    let stale_bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 10);
    let request = TsModuleRequest::new("react", TsRequestStyle::Import);
    let direct = resolver.resolve(&request, &context()).unwrap();
    let stale_validation = resolver.validate_resolution_index_bundle(&stale_bundle, 500, 60);
    let stale_indexed = resolver
        .resolve_with_index_or_fallback(&request, &context(), &stale_bundle, 500, 60)
        .unwrap();

    assert_eq!(
        stale_validation.reason,
        Some(TsResolutionIndexFallbackReason::ArtifactAgeExceeded)
    );
    assert_eq!(direct.resolved_path, stale_indexed.resolved_path);

    let mut changed_resolver = seeded_resolver();
    changed_resolver.register_file("/repo/node_modules/react/dist/additional.mjs");
    let mismatch_validation =
        changed_resolver.validate_resolution_index_bundle(&stale_bundle, 40, 3_600);
    let mismatch_indexed = changed_resolver
        .resolve_with_index_or_fallback(&request, &context(), &stale_bundle, 40, 3_600)
        .unwrap();

    assert_eq!(
        mismatch_validation.reason,
        Some(TsResolutionIndexFallbackReason::WorkspaceFingerprintMismatch)
    );
    assert_eq!(direct.resolved_path, mismatch_indexed.resolved_path);
}

#[test]
fn zero_attempt_policy_marks_collision_search_exhausted() {
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle_with_policy(
        "2026-03-09T00:00:00Z",
        100,
        &TsResolutionIndexBuildPolicy {
            max_salt_attempts: 0,
        },
    );
    let package = bundle.export_map_hash_catalog.package("react").unwrap();

    assert!(package.exact_export_mphf.is_none());
    assert!(package.hot_subpath_mphf.is_none());
    assert!(
        package
            .fallback_reasons
            .contains(&TsResolutionIndexFallbackReason::CollisionSearchExhausted)
    );
}

#[test]
fn artifact_writer_emits_required_bundle() {
    let dir = unique_temp_dir("artifacts");
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let validation = resolver.validate_resolution_index_bundle(&bundle, 120, 300);

    let manifest = write_ts_resolution_index_artifacts(
        &dir,
        "rgc-406a",
        &[
            "cargo check -p frankenengine-engine --test module_resolution_index".to_string(),
            "cargo test -p frankenengine-engine --test module_resolution_index".to_string(),
        ],
        &bridge_traces(),
        &bundle,
        &validation,
        &[TsResolutionIndexStepLog {
            name: "test".to_string(),
            contents: "step log".to_string(),
        }],
    )
    .unwrap();

    assert_eq!(
        manifest.schema_version,
        "rgc.ts-module-resolution.index.manifest.v1"
    );
    for required in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "module_art_index_report.json",
        "export_map_hash_catalog.json",
        "module_index_identity_report.json",
    ] {
        assert!(dir.join(required).exists(), "missing {required}");
    }
    assert!(dir.join("step_logs").exists());

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn module_resolution_index_artifact_bridge_emits_bundle_when_env_is_set() {
    let Some(artifact_dir) = std::env::var_os("RGC_MODULE_RESOLUTION_INDEX_ARTIFACT_DIR") else {
        return;
    };
    let artifact_dir = PathBuf::from(artifact_dir);
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let validation = resolver.validate_resolution_index_bundle(&bundle, 120, 300);

    write_ts_resolution_index_artifacts(
        &artifact_dir,
        "rgc-406a",
        &bridge_commands(),
        &bridge_traces(),
        &bundle,
        &validation,
        &[],
    )
    .unwrap();
}

// ── Serde roundtrip tests ──────────────────────────────────────────────

#[test]
fn serde_roundtrip_ts_module_resolution_config() {
    let config = base_config();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: TsModuleResolutionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, deserialized);
}

#[test]
fn serde_roundtrip_ts_module_resolution_mode_all_variants() {
    for mode in [
        TsModuleResolutionMode::Node16,
        TsModuleResolutionMode::NodeNext,
        TsModuleResolutionMode::Bundler,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: TsModuleResolutionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }
}

#[test]
fn serde_roundtrip_ts_request_style_both_variants() {
    for style in [TsRequestStyle::Import, TsRequestStyle::Require] {
        let json = serde_json::to_string(&style).unwrap();
        let deserialized: TsRequestStyle = serde_json::from_str(&json).unwrap();
        assert_eq!(style, deserialized);
    }
}

#[test]
fn serde_roundtrip_ts_resolution_index_fallback_reason_all_variants() {
    let variants = [
        TsResolutionIndexFallbackReason::ArtifactAgeExceeded,
        TsResolutionIndexFallbackReason::WorkspaceFingerprintMismatch,
        TsResolutionIndexFallbackReason::IndexFingerprintMismatch,
        TsResolutionIndexFallbackReason::CollisionSearchExhausted,
        TsResolutionIndexFallbackReason::UnsupportedWildcardExport,
        TsResolutionIndexFallbackReason::PackageMissingFromIndex,
        TsResolutionIndexFallbackReason::ExportMissingFromIndex,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let deserialized: TsResolutionIndexFallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, deserialized);
    }
}

// ── Resolver: unknown package ──────────────────────────────────────────

#[test]
fn resolve_unknown_package_returns_error() {
    let resolver = seeded_resolver();
    let request = TsModuleRequest::new("nonexistent-pkg", TsRequestStyle::Import);
    let result = resolver.resolve(&request, &context());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::ModuleNotFound);
}

// ── Resolver: require style selects require condition ──────────────────

#[test]
fn resolve_with_require_style_picks_require_target() {
    let resolver = seeded_resolver();
    let request = TsModuleRequest::new("react", TsRequestStyle::Require);
    let outcome = resolver.resolve(&request, &context()).unwrap();
    assert_eq!(
        outcome.resolved_path,
        "/repo/node_modules/react/dist/index.cjs"
    );
    assert_eq!(outcome.selected_condition.as_deref(), Some("require"));
}

// ── Empty resolver ─────────────────────────────────────────────────────

#[test]
fn empty_resolver_returns_empty_bundle() {
    let resolver = DeterministicTsModuleResolver::new(base_config());
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    assert_eq!(bundle.module_art_index_report.package_count, 0);
    assert_eq!(bundle.module_art_index_report.terminal_count, 0);
    assert_eq!(bundle.export_map_hash_catalog.indexed_package_count, 0);
    assert!(bundle.export_map_hash_catalog.packages.is_empty());
}

// ── TsResolutionContext creation and field access ──────────────────────

#[test]
fn ts_resolution_context_creation_and_field_access() {
    let ctx = TsResolutionContext::new("t1", "d1", "p1");
    assert_eq!(ctx.trace_id, "t1");
    assert_eq!(ctx.decision_id, "d1");
    assert_eq!(ctx.policy_id, "p1");

    // Serde roundtrip
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: TsResolutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

// ── TsModuleRequest creation and field access ──────────────────────────

#[test]
fn ts_module_request_creation_and_field_access() {
    let req = TsModuleRequest::new("lodash", TsRequestStyle::Import);
    assert_eq!(req.specifier, "lodash");
    assert!(req.referrer.is_none());
    assert_eq!(req.style, TsRequestStyle::Import);
}

#[test]
fn ts_module_request_with_referrer() {
    let req =
        TsModuleRequest::new("./utils", TsRequestStyle::Import).with_referrer("/repo/src/index.ts");
    assert_eq!(req.referrer.as_deref(), Some("/repo/src/index.ts"));
}

// ── TsPackageDefinition builder chain ──────────────────────────────────

#[test]
fn ts_package_definition_builder_chain() {
    let pkg = TsPackageDefinition::new("my-lib", "/repo/node_modules/my-lib")
        .with_export(".", export_target("import", "./dist/index.mjs"))
        .with_export("./sub", export_target("import", "./dist/sub.mjs"));
    assert_eq!(pkg.package_name, "my-lib");
    assert_eq!(pkg.package_root, "/repo/node_modules/my-lib");
    assert_eq!(pkg.exports.len(), 2);
    assert!(pkg.exports.contains_key("."));
    assert!(pkg.exports.contains_key("./sub"));
}

// ── Export target with fallback ────────────────────────────────────────

#[test]
fn export_target_with_fallback_is_used() {
    let target = TsPackageExportTarget {
        condition_targets: BTreeMap::new(),
        fallback_target: Some("./dist/fallback.js".to_string()),
    };

    let mut resolver = DeterministicTsModuleResolver::new(base_config());
    resolver.register_file("/repo/node_modules/fb-pkg/dist/fallback.js");
    resolver.register_package(
        TsPackageDefinition::new("fb-pkg", "/repo/node_modules/fb-pkg").with_export(".", target),
    );

    let outcome = resolver
        .resolve(
            &TsModuleRequest::new("fb-pkg", TsRequestStyle::Import),
            &context(),
        )
        .unwrap();
    assert_eq!(
        outcome.resolved_path,
        "/repo/node_modules/fb-pkg/dist/fallback.js"
    );
    assert_eq!(outcome.selected_condition.as_deref(), Some("fallback"));
}

// ── Build policy with different max_salt_attempts ──────────────────────

#[test]
fn build_policy_max_salt_attempts_one_succeeds() {
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle_with_policy(
        "2026-03-09T00:00:00Z",
        100,
        &TsResolutionIndexBuildPolicy {
            max_salt_attempts: 1,
        },
    );
    // With only 1 attempt, mphf may or may not be found depending on hash.
    // Either way the bundle must be valid and contain the package.
    assert!(bundle.export_map_hash_catalog.package("react").is_some());
}

#[test]
fn build_policy_default_has_large_salt_budget() {
    let default_policy = TsResolutionIndexBuildPolicy::default();
    assert_eq!(default_policy.max_salt_attempts, 4_096);
}

// ── Bundle hash determinism across runs ────────────────────────────────

#[test]
fn bundle_hash_determinism_across_separate_resolvers() {
    let resolver_a = seeded_resolver();
    let resolver_b = seeded_resolver();
    let bundle_a = resolver_a.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let bundle_b = resolver_b.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    assert_eq!(
        bundle_a.module_index_identity_report.index_fingerprint,
        bundle_b.module_index_identity_report.index_fingerprint
    );
    assert_eq!(
        bundle_a.module_index_identity_report.workspace_fingerprint,
        bundle_b.module_index_identity_report.workspace_fingerprint
    );
}

// ── Validation of fresh bundle passes ──────────────────────────────────

#[test]
fn validation_of_fresh_bundle_passes() {
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let validation = resolver.validate_resolution_index_bundle(&bundle, 200, 3_600);
    assert!(validation.accepted);
    assert!(validation.reason.is_none());
    assert_eq!(validation.artifact_age_seconds, 100);
    assert_eq!(validation.max_age_seconds, 3_600);
}

// ── Step log content in artifacts ──────────────────────────────────────

#[test]
fn step_log_content_is_written_to_artifacts() {
    let dir = unique_temp_dir("step_logs");
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let validation = resolver.validate_resolution_index_bundle(&bundle, 120, 300);

    let logs = vec![
        TsResolutionIndexStepLog {
            name: "build_index".to_string(),
            contents: "step one output".to_string(),
        },
        TsResolutionIndexStepLog {
            name: "validate".to_string(),
            contents: "step two output".to_string(),
        },
    ];

    write_ts_resolution_index_artifacts(
        &dir,
        "step-log-test",
        &["cargo test".to_string()],
        &bridge_traces(),
        &bundle,
        &validation,
        &logs,
    )
    .unwrap();

    let step_logs_dir = dir.join("step_logs");
    assert!(step_logs_dir.exists());

    let step1_path = step_logs_dir.join("step_001_build_index.log");
    let step2_path = step_logs_dir.join("step_002_validate.log");
    assert!(step1_path.exists(), "step 1 log file should exist");
    assert!(step2_path.exists(), "step 2 log file should exist");
    assert_eq!(fs::read_to_string(&step1_path).unwrap(), "step one output");
    assert_eq!(fs::read_to_string(&step2_path).unwrap(), "step two output");

    fs::remove_dir_all(&dir).unwrap();
}

// ── Multiple packages in a single resolver ─────────────────────────────

#[test]
fn multiple_packages_in_single_resolver() {
    let mut resolver = DeterministicTsModuleResolver::new(base_config());
    resolver.register_file("/repo/node_modules/alpha/dist/index.mjs");
    resolver.register_file("/repo/node_modules/beta/dist/main.mjs");
    resolver.register_package(
        TsPackageDefinition::new("alpha", "/repo/node_modules/alpha")
            .with_export(".", export_target("import", "./dist/index.mjs")),
    );
    resolver.register_package(
        TsPackageDefinition::new("beta", "/repo/node_modules/beta")
            .with_export(".", export_target("import", "./dist/main.mjs")),
    );

    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    assert_eq!(bundle.module_art_index_report.package_count, 2);
    assert!(
        bundle
            .module_art_index_report
            .lookup_package("alpha")
            .is_some()
    );
    assert!(
        bundle
            .module_art_index_report
            .lookup_package("beta")
            .is_some()
    );

    let alpha_outcome = resolver
        .resolve(
            &TsModuleRequest::new("alpha", TsRequestStyle::Import),
            &context(),
        )
        .unwrap();
    assert_eq!(
        alpha_outcome.resolved_path,
        "/repo/node_modules/alpha/dist/index.mjs"
    );

    let beta_outcome = resolver
        .resolve(
            &TsModuleRequest::new("beta", TsRequestStyle::Import),
            &context(),
        )
        .unwrap();
    assert_eq!(
        beta_outcome.resolved_path,
        "/repo/node_modules/beta/dist/main.mjs"
    );
}

// ── Mode enum serde rename ─────────────────────────────────────────────

#[test]
fn mode_enum_serde_produces_snake_case() {
    assert_eq!(
        serde_json::to_string(&TsModuleResolutionMode::Node16).unwrap(),
        "\"node16\""
    );
    assert_eq!(
        serde_json::to_string(&TsModuleResolutionMode::NodeNext).unwrap(),
        "\"node_next\""
    );
    assert_eq!(
        serde_json::to_string(&TsModuleResolutionMode::Bundler).unwrap(),
        "\"bundler\""
    );
}

#[test]
fn default_mode_is_node_next() {
    let mode = TsModuleResolutionMode::default();
    assert_eq!(mode, TsModuleResolutionMode::NodeNext);
}

// ── Duplicate file registration is idempotent ──────────────────────────

#[test]
fn duplicate_file_registration_is_idempotent() {
    let mut resolver = DeterministicTsModuleResolver::new(base_config());
    resolver.register_file("/repo/src/main.ts");
    let bundle_a = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    resolver.register_file("/repo/src/main.ts");
    let bundle_b = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    assert_eq!(
        bundle_a.module_index_identity_report.files_fingerprint,
        bundle_b.module_index_identity_report.files_fingerprint
    );
}

// ── Package export lookup for non-existent subpath ─────────────────────

#[test]
fn package_export_lookup_for_nonexistent_subpath_returns_error() {
    let resolver = seeded_resolver();
    let request = TsModuleRequest::new("react/no-such-export", TsRequestStyle::Import);
    let result = resolver.resolve(&request, &context());
    // react has exports ".", "./jsx-runtime", "./*". The "./*" wildcard will match
    // "no-such-export" => "./dist/wild/no-such-export.mjs" but no file registered for that.
    assert!(result.is_err());
}

// ── Wildcard export matching ───────────────────────────────────────────

#[test]
fn wildcard_export_matching_resolves_registered_file() {
    let resolver = seeded_resolver();
    let request = TsModuleRequest::new("react/tool", TsRequestStyle::Import);
    let outcome = resolver.resolve(&request, &context()).unwrap();
    // The wildcard "./*" maps to "./dist/wild/*.mjs", so "react/tool" -> "./dist/wild/tool.mjs"
    assert_eq!(
        outcome.resolved_path,
        "/repo/node_modules/react/dist/wild/tool.mjs"
    );
    assert_eq!(outcome.package_name.as_deref(), Some("react"));
}

// ── Index bundle serde roundtrip ───────────────────────────────────────

#[test]
fn index_bundle_serde_roundtrip() {
    let resolver = seeded_resolver();
    let bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: frankenengine_engine::ts_module_resolution::TsModuleResolutionIndexBundle =
        serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}

// ── Fallback reason stable codes ───────────────────────────────────────

#[test]
fn fallback_reason_stable_codes_are_unique_and_prefixed() {
    let variants = [
        TsResolutionIndexFallbackReason::ArtifactAgeExceeded,
        TsResolutionIndexFallbackReason::WorkspaceFingerprintMismatch,
        TsResolutionIndexFallbackReason::IndexFingerprintMismatch,
        TsResolutionIndexFallbackReason::CollisionSearchExhausted,
        TsResolutionIndexFallbackReason::UnsupportedWildcardExport,
        TsResolutionIndexFallbackReason::PackageMissingFromIndex,
        TsResolutionIndexFallbackReason::ExportMissingFromIndex,
    ];
    let mut codes = std::collections::BTreeSet::new();
    for variant in &variants {
        let code = variant.stable_code();
        assert!(
            code.starts_with("FE-TSRES-IDX-"),
            "stable code '{code}' must start with FE-TSRES-IDX-"
        );
        assert!(codes.insert(code), "duplicate stable code: {code}");
    }
    assert_eq!(codes.len(), variants.len());
}

// ── Empty specifier returns error ──────────────────────────────────────

#[test]
fn empty_specifier_returns_empty_specifier_error() {
    let resolver = seeded_resolver();
    let request = TsModuleRequest::new("", TsRequestStyle::Import);
    let result = resolver.resolve(&request, &context());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::EmptySpecifier);
    assert!(err.to_string().contains("FE-TSRES-0001"));
}

// ── Relative specifier without referrer ────────────────────────────────

#[test]
fn relative_specifier_without_referrer_returns_missing_referrer_error() {
    let resolver = seeded_resolver();
    let request = TsModuleRequest::new("./local", TsRequestStyle::Import);
    let result = resolver.resolve(&request, &context());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, TsResolutionErrorCode::MissingReferrer);
}

// ── Validation rejects index fingerprint mismatch ──────────────────────

#[test]
fn validation_rejects_tampered_bundle_as_index_fingerprint_mismatch() {
    let resolver = seeded_resolver();
    let mut bundle = resolver.build_resolution_index_bundle("2026-03-09T00:00:00Z", 100);
    // Tamper with the art index to break the index fingerprint
    bundle.module_art_index_report.node_count = 999;
    let validation = resolver.validate_resolution_index_bundle(&bundle, 200, 3_600);
    assert!(!validation.accepted);
    assert_eq!(
        validation.reason,
        Some(TsResolutionIndexFallbackReason::IndexFingerprintMismatch)
    );
}
