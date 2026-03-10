//! Enrichment integration tests for the migration_kit module.
//!
//! Extends integration coverage with: JSON field stability, Debug distinctness,
//! error code exact values, known-API database verification, capability
//! confidence thresholds, combined remediation categories, timing divergence
//! paths, non-default config effects, and cross-function edge cases.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::migration_kit::{
    ApiSupportLevel, ApiUsageEntry, BehaviorDivergence, BehaviorValidationReport,
    CapabilityInferenceResult, CompatibilityReport, DependencyEntry, DivergenceKind,
    DivergenceSeverity, InferredCapabilityKind, LockstepTestResult, ManifestGenerationInput,
    MigrationConfig, MigrationEvent, MigrationKitError, MigrationManifest, RemediationCategory,
    RemediationEffort, RemediationStep, SourceFile, SourceRuntime, analyze_package,
    compute_migration_readiness, emit_migration_event, generate_manifest, generate_remediation,
    infer_capabilities, lookup_api, validate_behavior,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// =========================================================================
// Helpers
// =========================================================================

fn node_config() -> MigrationConfig {
    MigrationConfig::default()
}

fn empty_compat() -> CompatibilityReport {
    CompatibilityReport {
        source_runtime: SourceRuntime::Node,
        total_apis_used: 0,
        fully_supported_count: 0,
        partially_supported_count: 0,
        unsupported_count: 0,
        deprecated_count: 0,
        polyfill_required_count: 0,
        compatibility_score_millionths: 1_000_000,
        api_entries: vec![],
        dependency_entries: vec![],
        report_content_hash: ContentHash::compute(b"e"),
    }
}

fn empty_behavior() -> BehaviorValidationReport {
    BehaviorValidationReport {
        total_test_cases: 1,
        passing_count: 1,
        divergence_count: 0,
        parity_score_millionths: 1_000_000,
        divergences: vec![],
        report_content_hash: ContentHash::compute(b"e"),
    }
}

fn empty_caps() -> CapabilityInferenceResult {
    CapabilityInferenceResult {
        inferred_capabilities: vec![],
        minimum_capability_set: BTreeSet::new(),
        recommended_capability_set: BTreeSet::new(),
        capability_hash: ContentHash::compute(b"e"),
    }
}

fn passing_result(name: &str) -> LockstepTestResult {
    LockstepTestResult {
        test_name: name.to_string(),
        node_output: "ok".to_string(),
        franken_output: "ok".to_string(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 500,
        franken_duration_us: 600,
    }
}

fn div_id_for(label: &[u8]) -> frankenengine_engine::engine_object_id::EngineObjectId {
    let schema_id =
        frankenengine_engine::engine_object_id::SchemaId::from_definition(b"BehaviorDivergence.v1");
    frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::EvidenceRecord,
        "migration-kit",
        &schema_id,
        label,
    )
    .unwrap()
}

// =========================================================================
// 1. Error code exact values — all 13 variants
// =========================================================================

#[test]
fn error_code_exact_values_all_13() {
    let cases: Vec<(MigrationKitError, &str)> = vec![
        (
            MigrationKitError::AnalysisFailed {
                detail: String::new(),
            },
            "FE-MK-0001",
        ),
        (
            MigrationKitError::ManifestGenerationFailed {
                detail: String::new(),
            },
            "FE-MK-0002",
        ),
        (
            MigrationKitError::CapabilityInferenceFailed {
                detail: String::new(),
            },
            "FE-MK-0003",
        ),
        (
            MigrationKitError::BehaviorValidationFailed {
                detail: String::new(),
            },
            "FE-MK-0004",
        ),
        (
            MigrationKitError::RemediationUnavailable {
                detail: String::new(),
            },
            "FE-MK-0005",
        ),
        (
            MigrationKitError::InvalidPackageJson {
                detail: String::new(),
            },
            "FE-MK-0006",
        ),
        (
            MigrationKitError::UnsupportedApiDetected {
                api: String::new(),
                detail: String::new(),
            },
            "FE-MK-0007",
        ),
        (
            MigrationKitError::IncompatibleDependency {
                name: String::new(),
                reason: String::new(),
            },
            "FE-MK-0008",
        ),
        (
            MigrationKitError::LockstepMismatch {
                runtime: String::new(),
                detail: String::new(),
            },
            "FE-MK-0009",
        ),
        (
            MigrationKitError::ReportGenerationFailed {
                detail: String::new(),
            },
            "FE-MK-0010",
        ),
        (
            MigrationKitError::DeterminismViolation {
                detail: String::new(),
            },
            "FE-MK-0011",
        ),
        (
            MigrationKitError::TooManyEntries {
                kind: String::new(),
                count: 0,
                max: 0,
            },
            "FE-MK-0012",
        ),
        (
            MigrationKitError::InternalError {
                detail: String::new(),
            },
            "FE-MK-0099",
        ),
    ];
    let mut seen = BTreeSet::new();
    for (err, expected_code) in &cases {
        assert_eq!(err.code(), *expected_code, "error code mismatch");
        assert!(
            seen.insert(*expected_code),
            "duplicate code {expected_code}"
        );
    }
    assert_eq!(seen.len(), 13);
}

// =========================================================================
// 2. Error Display exact messages
// =========================================================================

#[test]
fn error_display_exact_analysis_failed() {
    let e = MigrationKitError::AnalysisFailed {
        detail: "timeout".into(),
    };
    assert_eq!(e.to_string(), "analysis failed: timeout");
}

#[test]
fn error_display_exact_unsupported_api() {
    let e = MigrationKitError::UnsupportedApiDetected {
        api: "eval".into(),
        detail: "forbidden".into(),
    };
    assert_eq!(e.to_string(), "unsupported API 'eval': forbidden");
}

#[test]
fn error_display_exact_incompatible_dependency() {
    let e = MigrationKitError::IncompatibleDependency {
        name: "sharp".into(),
        reason: "native".into(),
    };
    assert_eq!(e.to_string(), "incompatible dependency 'sharp': native");
}

#[test]
fn error_display_exact_too_many_entries() {
    let e = MigrationKitError::TooManyEntries {
        kind: "api".into(),
        count: 200,
        max: 100,
    };
    assert_eq!(e.to_string(), "too many api entries: 200 exceeds max 100");
}

// =========================================================================
// 3. std::error::Error trait
// =========================================================================

#[test]
fn all_error_variants_implement_std_error() {
    let variants: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(MigrationKitError::AnalysisFailed { detail: "a".into() }),
        Box::new(MigrationKitError::ManifestGenerationFailed { detail: "b".into() }),
        Box::new(MigrationKitError::CapabilityInferenceFailed { detail: "c".into() }),
        Box::new(MigrationKitError::BehaviorValidationFailed { detail: "d".into() }),
        Box::new(MigrationKitError::RemediationUnavailable { detail: "e".into() }),
        Box::new(MigrationKitError::InvalidPackageJson { detail: "f".into() }),
        Box::new(MigrationKitError::UnsupportedApiDetected {
            api: "g".into(),
            detail: "h".into(),
        }),
        Box::new(MigrationKitError::IncompatibleDependency {
            name: "i".into(),
            reason: "j".into(),
        }),
        Box::new(MigrationKitError::LockstepMismatch {
            runtime: "k".into(),
            detail: "l".into(),
        }),
        Box::new(MigrationKitError::ReportGenerationFailed { detail: "m".into() }),
        Box::new(MigrationKitError::DeterminismViolation { detail: "n".into() }),
        Box::new(MigrationKitError::TooManyEntries {
            kind: "o".into(),
            count: 1,
            max: 2,
        }),
        Box::new(MigrationKitError::InternalError { detail: "p".into() }),
    ];
    let mut displays = BTreeSet::new();
    for v in &variants {
        let msg = format!("{v}");
        assert!(!msg.is_empty());
        displays.insert(msg);
    }
    assert_eq!(
        displays.len(),
        13,
        "all 13 variants produce distinct messages"
    );
}

// =========================================================================
// 4. Error serde roundtrip all 13 variants
// =========================================================================

#[test]
fn error_serde_roundtrip_all_13_variants() {
    let variants = vec![
        MigrationKitError::AnalysisFailed { detail: "a".into() },
        MigrationKitError::ManifestGenerationFailed { detail: "b".into() },
        MigrationKitError::CapabilityInferenceFailed { detail: "c".into() },
        MigrationKitError::BehaviorValidationFailed { detail: "d".into() },
        MigrationKitError::RemediationUnavailable { detail: "e".into() },
        MigrationKitError::InvalidPackageJson { detail: "f".into() },
        MigrationKitError::UnsupportedApiDetected {
            api: "g".into(),
            detail: "h".into(),
        },
        MigrationKitError::IncompatibleDependency {
            name: "i".into(),
            reason: "j".into(),
        },
        MigrationKitError::LockstepMismatch {
            runtime: "k".into(),
            detail: "l".into(),
        },
        MigrationKitError::ReportGenerationFailed { detail: "m".into() },
        MigrationKitError::DeterminismViolation { detail: "n".into() },
        MigrationKitError::TooManyEntries {
            kind: "o".into(),
            count: 99,
            max: 50,
        },
        MigrationKitError::InternalError { detail: "p".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: MigrationKitError = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &back, "roundtrip failed for {}", v.code());
    }
}

// =========================================================================
// 5. JSON field name stability
// =========================================================================

#[test]
fn json_field_stability_migration_config() {
    let config = MigrationConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("source_runtime").is_some());
    assert!(v.get("analyze_dependencies").is_some());
    assert!(v.get("infer_capabilities").is_some());
    assert!(v.get("run_behavior_validation").is_some());
    assert!(v.get("min_compatibility_score_millionths").is_some());
    assert!(v.get("max_divergence_count").is_some());
    assert!(v.get("deterministic_seed").is_some());
}

#[test]
fn json_field_stability_lockstep_test_result() {
    let r = LockstepTestResult {
        test_name: "t".into(),
        node_output: "n".into(),
        franken_output: "f".into(),
        node_exit_code: 0,
        franken_exit_code: 1,
        node_duration_us: 10,
        franken_duration_us: 20,
    };
    let json = serde_json::to_string(&r).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("test_name").is_some());
    assert!(v.get("node_output").is_some());
    assert!(v.get("franken_output").is_some());
    assert!(v.get("node_exit_code").is_some());
    assert!(v.get("franken_exit_code").is_some());
    assert!(v.get("node_duration_us").is_some());
    assert!(v.get("franken_duration_us").is_some());
}

#[test]
fn json_field_stability_migration_event() {
    let event = MigrationEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: Some("FE-MK-0001".into()),
        details: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("trace_id").is_some());
    assert!(v.get("decision_id").is_some());
    assert!(v.get("component").is_some());
    assert!(v.get("event").is_some());
    assert!(v.get("outcome").is_some());
    assert!(v.get("error_code").is_some());
    assert!(v.get("details").is_some());
}

#[test]
fn json_field_stability_compatibility_report() {
    let report = analyze_package(r#"{"name":"x","version":"1.0.0"}"#, &node_config()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("source_runtime").is_some());
    assert!(v.get("total_apis_used").is_some());
    assert!(v.get("fully_supported_count").is_some());
    assert!(v.get("compatibility_score_millionths").is_some());
    assert!(v.get("api_entries").is_some());
    assert!(v.get("dependency_entries").is_some());
    assert!(v.get("report_content_hash").is_some());
}

#[test]
fn json_field_stability_behavior_validation_report() {
    let results = vec![passing_result("t")];
    let report = validate_behavior(&results, &node_config()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("total_test_cases").is_some());
    assert!(v.get("passing_count").is_some());
    assert!(v.get("divergence_count").is_some());
    assert!(v.get("parity_score_millionths").is_some());
    assert!(v.get("divergences").is_some());
    assert!(v.get("report_content_hash").is_some());
}

#[test]
fn json_field_stability_manifest() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "field-test".into(),
        source_version: "1.0.0".into(),
        entry_point: "index.js".into(),
        compatibility: empty_compat(),
        behavior: empty_behavior(),
        capabilities: empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("manifest_id").is_some());
    assert!(v.get("source_runtime").is_some());
    assert!(v.get("source_package_name").is_some());
    assert!(v.get("franken_extension_name").is_some());
    assert!(v.get("franken_extension_version").is_some());
    assert!(v.get("required_capabilities").is_some());
    assert!(v.get("compatibility_score_millionths").is_some());
    assert!(v.get("parity_score_millionths").is_some());
    assert!(v.get("migration_readiness_score_millionths").is_some());
    assert!(v.get("manifest_content_hash").is_some());
    assert!(v.get("created_epoch").is_some());
}

// =========================================================================
// 6. Debug distinctness — enum variants
// =========================================================================

#[test]
fn debug_distinct_source_runtime() {
    let variants = [SourceRuntime::Node, SourceRuntime::Bun];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 2);
}

#[test]
fn debug_distinct_api_support_level() {
    let variants = [
        ApiSupportLevel::FullySupported,
        ApiSupportLevel::PartiallySupported,
        ApiSupportLevel::Unsupported,
        ApiSupportLevel::Deprecated,
        ApiSupportLevel::RequiresPolyfill,
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn debug_distinct_divergence_kind() {
    let variants = [
        DivergenceKind::SemanticDifference,
        DivergenceKind::TimingDifference,
        DivergenceKind::OutputFormatDifference,
        DivergenceKind::ErrorBehaviorDifference,
        DivergenceKind::MissingFeature,
        DivergenceKind::SecurityPolicyDifference,
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 6);
}

#[test]
fn debug_distinct_divergence_severity() {
    let variants = [
        DivergenceSeverity::Critical,
        DivergenceSeverity::High,
        DivergenceSeverity::Medium,
        DivergenceSeverity::Low,
        DivergenceSeverity::Informational,
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn debug_distinct_inferred_capability_kind() {
    let variants = [
        InferredCapabilityKind::FileSystem,
        InferredCapabilityKind::Network,
        InferredCapabilityKind::ProcessSpawn,
        InferredCapabilityKind::EnvironmentAccess,
        InferredCapabilityKind::CryptoAccess,
        InferredCapabilityKind::TimerAccess,
        InferredCapabilityKind::WorkerThreads,
        InferredCapabilityKind::ChildProcess,
        InferredCapabilityKind::DynamicImport,
        InferredCapabilityKind::WasmExecution,
        InferredCapabilityKind::SharedMemory,
        InferredCapabilityKind::NativeAddon,
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 12);
}

#[test]
fn debug_distinct_remediation_category() {
    let variants = [
        RemediationCategory::ApiReplacement,
        RemediationCategory::DependencySwap,
        RemediationCategory::ConfigChange,
        RemediationCategory::CodeRefactor,
        RemediationCategory::PolyfillAddition,
        RemediationCategory::SecurityPolicyUpdate,
        RemediationCategory::FeatureDisable,
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 7);
}

#[test]
fn debug_distinct_remediation_effort() {
    let variants = [
        RemediationEffort::Trivial,
        RemediationEffort::Low,
        RemediationEffort::Medium,
        RemediationEffort::High,
        RemediationEffort::Significant,
    ];
    let dbgs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbgs.len(), 5);
}

// =========================================================================
// 7. Known API database — lookup_api coverage
// =========================================================================

#[test]
fn lookup_api_fs_read_file() {
    let api = lookup_api("fs", "readFile").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
    assert_eq!(api.module_name, "fs");
}

#[test]
fn lookup_api_fs_write_file() {
    let api = lookup_api("fs", "writeFile").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
}

#[test]
fn lookup_api_path_join() {
    let api = lookup_api("path", "join").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
}

#[test]
fn lookup_api_http_create_server() {
    let api = lookup_api("http", "createServer").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::PartiallySupported);
}

#[test]
fn lookup_api_child_process_exec() {
    let api = lookup_api("child_process", "exec").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Unsupported);
}

#[test]
fn lookup_api_child_process_spawn() {
    let api = lookup_api("child_process", "spawn").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Unsupported);
}

#[test]
fn lookup_api_child_process_fork() {
    let api = lookup_api("child_process", "fork").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Unsupported);
}

#[test]
fn lookup_api_crypto_create_hash() {
    let api = lookup_api("crypto", "createHash").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
}

#[test]
fn lookup_api_crypto_random_bytes() {
    let api = lookup_api("crypto", "randomBytes").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::PartiallySupported);
}

#[test]
fn lookup_api_vm_create_context() {
    let api = lookup_api("vm", "createContext").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Unsupported);
}

#[test]
fn lookup_api_querystring_deprecated() {
    let api = lookup_api("querystring", "parse").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Deprecated);
}

#[test]
fn lookup_api_punycode_deprecated() {
    let api = lookup_api("punycode", "encode").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Deprecated);
}

#[test]
fn lookup_api_unknown_returns_none() {
    assert!(lookup_api("nonexistent_module", "foo").is_none());
    assert!(lookup_api("fs", "nonexistent_fn").is_none());
}

#[test]
fn lookup_api_timers_set_timeout() {
    let api = lookup_api("timers", "setTimeout").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
}

#[test]
fn lookup_api_buffer() {
    let api = lookup_api("buffer", "Buffer").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
}

#[test]
fn lookup_api_events_emitter() {
    let api = lookup_api("events", "EventEmitter").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
}

#[test]
fn lookup_api_dns_unsupported() {
    let api = lookup_api("dns", "resolve").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Unsupported);
}

#[test]
fn lookup_api_dgram_unsupported() {
    let api = lookup_api("dgram", "createSocket").unwrap();
    assert_eq!(api.support_level, ApiSupportLevel::Unsupported);
}

// =========================================================================
// 8. Known dependency classifications
// =========================================================================

#[test]
fn known_compatible_dependencies() {
    let pkg = r#"{"name":"x","version":"1.0.0","dependencies":{
        "lodash":"^4","moment":"^2","date-fns":"^3","uuid":"^9",
        "chalk":"^5","commander":"^11","yargs":"^17","zod":"^3",
        "dotenv":"^16"
    }}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    for dep in &report.dependency_entries {
        assert!(dep.compatible, "expected {} to be compatible", dep.name);
    }
}

#[test]
fn known_incompatible_dependencies() {
    let pkg = r#"{"name":"x","version":"1.0.0","dependencies":{
        "express":"^4","axios":"^1","sharp":"^0.33",
        "bcrypt":"^5","sqlite3":"^5","better-sqlite3":"^9",
        "ws":"^8","pg":"^8","redis":"^4","mongoose":"^7"
    }}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    for dep in &report.dependency_entries {
        assert!(!dep.compatible, "expected {} to be incompatible", dep.name);
    }
}

#[test]
fn dev_dependencies_typescript_jest_vitest_compatible() {
    let pkg = r#"{"name":"x","version":"1.0.0","devDependencies":{
        "typescript":"^5","jest":"^29","vitest":"^1"
    }}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert_eq!(report.dependency_entries.len(), 3);
    assert!(report.dependency_entries.iter().all(|d| d.compatible));
}

// =========================================================================
// 9. Capability inference — confidence threshold boundary
// =========================================================================

#[test]
fn capability_at_threshold_800k_in_minimum_set() {
    // setTimeout has confidence 800_000 which is >= 800_000 threshold
    let files = vec![SourceFile {
        path: "a.js".into(),
        content: "setTimeout(fn, 100)".into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    assert!(result.minimum_capability_set.contains("cap:timer"));
    assert!(result.recommended_capability_set.contains("cap:timer"));
}

#[test]
fn capability_below_threshold_only_in_recommended() {
    // "new Worker" pattern has confidence 700_000 < 800_000 threshold
    let files = vec![SourceFile {
        path: "w.js".into(),
        content: "const w = new Worker('./w.js')".into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    assert!(
        !result.minimum_capability_set.contains("cap:worker"),
        "700k < 800k threshold: should NOT be in minimum set"
    );
    assert!(
        result.recommended_capability_set.contains("cap:worker"),
        "should always be in recommended set"
    );
}

#[test]
fn capability_high_confidence_overrides_low_in_same_kind() {
    // Both "new Worker" (700k) and require("worker_threads") (900k) match WorkerThreads
    let files = vec![SourceFile {
        path: "pool.js".into(),
        content: r#"const { Worker } = require("worker_threads");
const w = new Worker('./child.js');"#
            .into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    let cap = result
        .inferred_capabilities
        .iter()
        .find(|c| c.kind == InferredCapabilityKind::WorkerThreads)
        .unwrap();
    assert_eq!(cap.confidence_millionths, 900_000, "max confidence wins");
    assert!(result.minimum_capability_set.contains("cap:worker"));
}

// =========================================================================
// 10. All 12 InferredCapabilityKind names
// =========================================================================

#[test]
fn all_capability_kind_names_start_with_cap() {
    let kinds = [
        InferredCapabilityKind::FileSystem,
        InferredCapabilityKind::Network,
        InferredCapabilityKind::ProcessSpawn,
        InferredCapabilityKind::EnvironmentAccess,
        InferredCapabilityKind::CryptoAccess,
        InferredCapabilityKind::TimerAccess,
        InferredCapabilityKind::WorkerThreads,
        InferredCapabilityKind::ChildProcess,
        InferredCapabilityKind::DynamicImport,
        InferredCapabilityKind::WasmExecution,
        InferredCapabilityKind::SharedMemory,
        InferredCapabilityKind::NativeAddon,
    ];
    let mut names = BTreeSet::new();
    for kind in &kinds {
        let name = kind.franken_capability_name();
        assert!(name.starts_with("cap:"), "{name} should start with cap:");
        names.insert(name);
    }
    assert_eq!(names.len(), 12, "all 12 names should be unique");
}

// =========================================================================
// 11. ApiSupportLevel helpers
// =========================================================================

#[test]
fn api_support_level_is_migration_blocker() {
    assert!(!ApiSupportLevel::FullySupported.is_migration_blocker());
    assert!(!ApiSupportLevel::PartiallySupported.is_migration_blocker());
    assert!(ApiSupportLevel::Unsupported.is_migration_blocker());
    assert!(!ApiSupportLevel::Deprecated.is_migration_blocker());
    assert!(!ApiSupportLevel::RequiresPolyfill.is_migration_blocker());
}

#[test]
fn api_support_level_weight_exact_values() {
    assert_eq!(
        ApiSupportLevel::FullySupported.compatibility_weight_millionths(),
        1_000_000
    );
    assert_eq!(
        ApiSupportLevel::PartiallySupported.compatibility_weight_millionths(),
        700_000
    );
    assert_eq!(
        ApiSupportLevel::Deprecated.compatibility_weight_millionths(),
        500_000
    );
    assert_eq!(
        ApiSupportLevel::RequiresPolyfill.compatibility_weight_millionths(),
        400_000
    );
    assert_eq!(
        ApiSupportLevel::Unsupported.compatibility_weight_millionths(),
        0
    );
}

// =========================================================================
// 12. DivergenceSeverity penalty exact values
// =========================================================================

#[test]
fn divergence_severity_penalty_exact_values() {
    assert_eq!(DivergenceSeverity::Critical.penalty_millionths(), 200_000);
    assert_eq!(DivergenceSeverity::High.penalty_millionths(), 100_000);
    assert_eq!(DivergenceSeverity::Medium.penalty_millionths(), 50_000);
    assert_eq!(DivergenceSeverity::Low.penalty_millionths(), 20_000);
    assert_eq!(DivergenceSeverity::Informational.penalty_millionths(), 0);
}

// =========================================================================
// 13. RemediationEffort weight exact values
// =========================================================================

#[test]
fn remediation_effort_weight_exact_values() {
    assert_eq!(RemediationEffort::Trivial.weight_millionths(), 100_000);
    assert_eq!(RemediationEffort::Low.weight_millionths(), 300_000);
    assert_eq!(RemediationEffort::Medium.weight_millionths(), 500_000);
    assert_eq!(RemediationEffort::High.weight_millionths(), 800_000);
    assert_eq!(
        RemediationEffort::Significant.weight_millionths(),
        1_000_000
    );
}

// =========================================================================
// 14. SourceRuntime Display
// =========================================================================

#[test]
fn source_runtime_display_exact() {
    assert_eq!(format!("{}", SourceRuntime::Node), "Node.js");
    assert_eq!(format!("{}", SourceRuntime::Bun), "Bun");
}

// =========================================================================
// 15. Serde roundtrips for leaf enums
// =========================================================================

#[test]
fn serde_roundtrip_source_runtime() {
    for rt in [SourceRuntime::Node, SourceRuntime::Bun] {
        let json = serde_json::to_string(&rt).unwrap();
        let back: SourceRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, back);
    }
}

#[test]
fn serde_roundtrip_api_support_level_all() {
    for level in [
        ApiSupportLevel::FullySupported,
        ApiSupportLevel::PartiallySupported,
        ApiSupportLevel::Unsupported,
        ApiSupportLevel::Deprecated,
        ApiSupportLevel::RequiresPolyfill,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let back: ApiSupportLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, back);
    }
}

#[test]
fn serde_roundtrip_divergence_kind_all() {
    for kind in [
        DivergenceKind::SemanticDifference,
        DivergenceKind::TimingDifference,
        DivergenceKind::OutputFormatDifference,
        DivergenceKind::ErrorBehaviorDifference,
        DivergenceKind::MissingFeature,
        DivergenceKind::SecurityPolicyDifference,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: DivergenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn serde_roundtrip_divergence_severity_all() {
    for sev in [
        DivergenceSeverity::Critical,
        DivergenceSeverity::High,
        DivergenceSeverity::Medium,
        DivergenceSeverity::Low,
        DivergenceSeverity::Informational,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: DivergenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn serde_roundtrip_inferred_capability_kind_all() {
    for kind in [
        InferredCapabilityKind::FileSystem,
        InferredCapabilityKind::Network,
        InferredCapabilityKind::ProcessSpawn,
        InferredCapabilityKind::EnvironmentAccess,
        InferredCapabilityKind::CryptoAccess,
        InferredCapabilityKind::TimerAccess,
        InferredCapabilityKind::WorkerThreads,
        InferredCapabilityKind::ChildProcess,
        InferredCapabilityKind::DynamicImport,
        InferredCapabilityKind::WasmExecution,
        InferredCapabilityKind::SharedMemory,
        InferredCapabilityKind::NativeAddon,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: InferredCapabilityKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn serde_roundtrip_remediation_category_all() {
    for cat in [
        RemediationCategory::ApiReplacement,
        RemediationCategory::DependencySwap,
        RemediationCategory::ConfigChange,
        RemediationCategory::CodeRefactor,
        RemediationCategory::PolyfillAddition,
        RemediationCategory::SecurityPolicyUpdate,
        RemediationCategory::FeatureDisable,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: RemediationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

#[test]
fn serde_roundtrip_remediation_effort_all() {
    for effort in [
        RemediationEffort::Trivial,
        RemediationEffort::Low,
        RemediationEffort::Medium,
        RemediationEffort::High,
        RemediationEffort::Significant,
    ] {
        let json = serde_json::to_string(&effort).unwrap();
        let back: RemediationEffort = serde_json::from_str(&json).unwrap();
        assert_eq!(effort, back);
    }
}

// =========================================================================
// 16. Serde roundtrips for structs
// =========================================================================

#[test]
fn serde_roundtrip_api_usage_entry() {
    let entry = ApiUsageEntry {
        api_name: "readFile".into(),
        module_path: "fs".into(),
        usage_count: 3,
        support_level: ApiSupportLevel::FullySupported,
        notes: "sandboxed".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ApiUsageEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn serde_roundtrip_dependency_entry() {
    let dep = DependencyEntry {
        name: "express".into(),
        version_spec: "^4.18.0".into(),
        compatible: false,
        migration_notes: "needs adapter".into(),
    };
    let json = serde_json::to_string(&dep).unwrap();
    let back: DependencyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(dep, back);
}

#[test]
fn serde_roundtrip_source_file() {
    let sf = SourceFile {
        path: "index.js".into(),
        content: "const x = 1;".into(),
    };
    let json = serde_json::to_string(&sf).unwrap();
    let back: SourceFile = serde_json::from_str(&json).unwrap();
    assert_eq!(sf, back);
}

#[test]
fn serde_roundtrip_remediation_step() {
    let schema_id =
        frankenengine_engine::engine_object_id::SchemaId::from_definition(b"RemediationPlan.v1");
    let step_id = frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::EvidenceRecord,
        "migration-kit",
        &schema_id,
        b"step-serde",
    )
    .unwrap();
    let step = RemediationStep {
        step_id,
        category: RemediationCategory::PolyfillAddition,
        effort: RemediationEffort::Low,
        title: "Add polyfill for X".into(),
        description: "Needed for compat".into(),
        before_snippet: "old()".into(),
        after_snippet: "polyfill()".into(),
        affected_files: vec!["lib.js".into()],
        priority_score_millionths: 600_000,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: RemediationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
}

#[test]
fn serde_roundtrip_capability_inference_result() {
    let files = vec![SourceFile {
        path: "app.js".into(),
        content: r#"const fs = require("fs"); process.env.X;"#.into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: CapabilityInferenceResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_roundtrip_manifest_via_generate() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Bun,
        source_package_name: "serde-pkg".into(),
        source_version: "2.0.0".into(),
        entry_point: "src/main.ts".into(),
        compatibility: empty_compat(),
        behavior: empty_behavior(),
        capabilities: empty_caps(),
        epoch: SecurityEpoch::from_raw(99),
    })
    .unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: MigrationManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// =========================================================================
// 17. MigrationConfig Default values
// =========================================================================

#[test]
fn migration_config_default_values() {
    let c = MigrationConfig::default();
    assert_eq!(c.source_runtime, SourceRuntime::Node);
    assert!(c.analyze_dependencies);
    assert!(c.infer_capabilities);
    assert!(c.run_behavior_validation);
    assert_eq!(c.min_compatibility_score_millionths, 800_000);
    assert_eq!(c.max_divergence_count, 100);
    assert_eq!(c.deterministic_seed, 42);
}

// =========================================================================
// 18. validate_behavior — timing divergence path
// =========================================================================

#[test]
fn validate_behavior_timing_divergence_over_2x() {
    let results = vec![LockstepTestResult {
        test_name: "slow-test".into(),
        node_output: "result_a".into(),
        franken_output: "result_b".into(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 100,
        franken_duration_us: 500, // 5x > 2x threshold
    }];
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.divergence_count, 1);
    assert_eq!(report.divergences[0].kind, DivergenceKind::TimingDifference);
}

#[test]
fn validate_behavior_no_timing_divergence_within_2x() {
    let results = vec![LockstepTestResult {
        test_name: "normal-test".into(),
        node_output: "aaa".into(),
        franken_output: "bbb".into(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 100,
        franken_duration_us: 150, // 1.5x < 2x threshold
    }];
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.divergence_count, 1);
    assert_eq!(
        report.divergences[0].kind,
        DivergenceKind::OutputFormatDifference
    );
}

// =========================================================================
// 19. validate_behavior — divergence severity classification
// =========================================================================

#[test]
fn validate_behavior_critical_both_output_and_exit_differ() {
    let results = vec![LockstepTestResult {
        test_name: "critical".into(),
        node_output: "expected".into(),
        franken_output: "crash".into(),
        node_exit_code: 0,
        franken_exit_code: 1,
        node_duration_us: 100,
        franken_duration_us: 100,
    }];
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.divergences[0].severity, DivergenceSeverity::Critical);
    assert_eq!(
        report.divergences[0].kind,
        DivergenceKind::SemanticDifference
    );
}

#[test]
fn validate_behavior_high_exit_code_only_mismatch() {
    let results = vec![LockstepTestResult {
        test_name: "exit-only".into(),
        node_output: "same".into(),
        franken_output: "same".into(),
        node_exit_code: 0,
        franken_exit_code: 1,
        node_duration_us: 100,
        franken_duration_us: 100,
    }];
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.divergences[0].severity, DivergenceSeverity::High);
    assert_eq!(
        report.divergences[0].kind,
        DivergenceKind::ErrorBehaviorDifference
    );
}

// =========================================================================
// 20. validate_behavior — divergence ID determinism
// =========================================================================

#[test]
fn validate_behavior_divergence_id_deterministic() {
    let results = vec![LockstepTestResult {
        test_name: "det-test".into(),
        node_output: "a".into(),
        franken_output: "b".into(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 50,
        franken_duration_us: 50,
    }];
    let r1 = validate_behavior(&results, &node_config()).unwrap();
    let r2 = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(
        r1.divergences[0].divergence_id,
        r2.divergences[0].divergence_id
    );
}

#[test]
fn validate_behavior_different_seed_different_ids() {
    let results = vec![LockstepTestResult {
        test_name: "seed-test".into(),
        node_output: "a".into(),
        franken_output: "b".into(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 50,
        franken_duration_us: 50,
    }];
    let config1 = MigrationConfig {
        deterministic_seed: 1,
        ..MigrationConfig::default()
    };
    let config2 = MigrationConfig {
        deterministic_seed: 2,
        ..MigrationConfig::default()
    };
    let r1 = validate_behavior(&results, &config1).unwrap();
    let r2 = validate_behavior(&results, &config2).unwrap();
    assert_ne!(
        r1.divergences[0].divergence_id, r2.divergences[0].divergence_id,
        "different seed should produce different divergence IDs"
    );
}

// =========================================================================
// 21. compute_migration_readiness — edge cases
// =========================================================================

#[test]
fn readiness_perfect_scores() {
    let compat = CompatibilityReport {
        compatibility_score_millionths: 1_000_000,
        ..empty_compat()
    };
    let behavior = BehaviorValidationReport {
        parity_score_millionths: 1_000_000,
        ..empty_behavior()
    };
    assert_eq!(compute_migration_readiness(&compat, &behavior), 1_000_000);
}

#[test]
fn readiness_40_60_weighting() {
    // compat=500k, parity=500k => 500k*0.4 + 500k*0.6 = 200k + 300k = 500k
    let compat = CompatibilityReport {
        compatibility_score_millionths: 500_000,
        ..empty_compat()
    };
    let behavior = BehaviorValidationReport {
        parity_score_millionths: 500_000,
        ..empty_behavior()
    };
    assert_eq!(compute_migration_readiness(&compat, &behavior), 500_000);
}

#[test]
fn readiness_critical_penalty_100k_each() {
    let compat = CompatibilityReport {
        compatibility_score_millionths: 1_000_000,
        ..empty_compat()
    };
    let behavior = BehaviorValidationReport {
        parity_score_millionths: 1_000_000,
        divergences: vec![
            BehaviorDivergence {
                divergence_id: div_id_for(b"c1"),
                kind: DivergenceKind::SemanticDifference,
                severity: DivergenceSeverity::Critical,
                test_case: "c1".into(),
                node_bun_result: "a".into(),
                franken_result: "b".into(),
                explanation: String::new(),
                remediation: String::new(),
            },
            BehaviorDivergence {
                divergence_id: div_id_for(b"c2"),
                kind: DivergenceKind::SemanticDifference,
                severity: DivergenceSeverity::Critical,
                test_case: "c2".into(),
                node_bun_result: "x".into(),
                franken_result: "y".into(),
                explanation: String::new(),
                remediation: String::new(),
            },
        ],
        ..empty_behavior()
    };
    // 1M*0.4 + 1M*0.6 - 2*100k = 1M - 200k = 800k
    assert_eq!(compute_migration_readiness(&compat, &behavior), 800_000);
}

#[test]
fn readiness_non_critical_divergences_no_penalty() {
    let compat = CompatibilityReport {
        compatibility_score_millionths: 1_000_000,
        ..empty_compat()
    };
    let behavior = BehaviorValidationReport {
        parity_score_millionths: 1_000_000,
        divergences: vec![BehaviorDivergence {
            divergence_id: div_id_for(b"hi"),
            kind: DivergenceKind::OutputFormatDifference,
            severity: DivergenceSeverity::High,
            test_case: "h".into(),
            node_bun_result: "a".into(),
            franken_result: "b".into(),
            explanation: String::new(),
            remediation: String::new(),
        }],
        ..empty_behavior()
    };
    // High severity divergence doesn't get penalty — only Critical does
    assert_eq!(compute_migration_readiness(&compat, &behavior), 1_000_000);
}

// =========================================================================
// 22. Combined remediation: unsupported + deprecated + incompat deps + critical divergence
// =========================================================================

#[test]
fn combined_remediation_all_categories() {
    let compat = CompatibilityReport {
        source_runtime: SourceRuntime::Node,
        total_apis_used: 2,
        fully_supported_count: 0,
        partially_supported_count: 0,
        unsupported_count: 1,
        deprecated_count: 1,
        polyfill_required_count: 0,
        compatibility_score_millionths: 250_000,
        api_entries: vec![
            ApiUsageEntry {
                api_name: "child_process.exec".into(),
                module_path: "child_process".into(),
                usage_count: 1,
                support_level: ApiSupportLevel::Unsupported,
                notes: "no shell".into(),
            },
            ApiUsageEntry {
                api_name: "url.parse".into(),
                module_path: "url".into(),
                usage_count: 2,
                support_level: ApiSupportLevel::Deprecated,
                notes: "use URL()".into(),
            },
        ],
        dependency_entries: vec![DependencyEntry {
            name: "sharp".into(),
            version_spec: "^0.33".into(),
            compatible: false,
            migration_notes: "native addon".into(),
        }],
        report_content_hash: ContentHash::compute(b"combined"),
    };
    let behavior = BehaviorValidationReport {
        total_test_cases: 2,
        passing_count: 1,
        divergence_count: 1,
        parity_score_millionths: 500_000,
        divergences: vec![BehaviorDivergence {
            divergence_id: div_id_for(b"crit"),
            kind: DivergenceKind::SemanticDifference,
            severity: DivergenceSeverity::Critical,
            test_case: "crash_test".into(),
            node_bun_result: "ok".into(),
            franken_result: "CRASH".into(),
            explanation: "fatal".into(),
            remediation: "fix".into(),
        }],
        report_content_hash: ContentHash::compute(b"combined"),
    };
    let caps = empty_caps();

    let steps = generate_remediation(&compat, &behavior, &caps).unwrap();

    // Should have all 4 categories
    let categories: BTreeSet<_> = steps.iter().map(|s| s.category).collect();
    assert!(categories.contains(&RemediationCategory::ApiReplacement));
    assert!(categories.contains(&RemediationCategory::DependencySwap));
    assert!(categories.contains(&RemediationCategory::CodeRefactor));

    // Should be sorted by priority descending
    for window in steps.windows(2) {
        assert!(window[0].priority_score_millionths >= window[1].priority_score_millionths);
    }

    assert!(
        steps.len() >= 4,
        "at least 4 steps: 1 unsupported + 1 deprecated + 1 dep + 1 behavior"
    );
}

// =========================================================================
// 23. analyze_package — CJS vs ESM entry detection
// =========================================================================

#[test]
fn analyze_package_cjs_entry_from_main() {
    let pkg = r#"{"name":"cjs","version":"1.0.0","main":"dist/bundle.js"}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.api_entries.iter().any(|e| e.api_name == "entry:cjs"));
}

#[test]
fn analyze_package_esm_entry_from_mjs() {
    let pkg = r#"{"name":"esm","version":"1.0.0","module":"dist/index.mjs"}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.api_entries.iter().any(|e| e.api_name == "entry:esm"));
}

#[test]
fn analyze_package_esm_entry_from_ts() {
    let pkg = r#"{"name":"ts","version":"1.0.0","main":"index.ts"}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.api_entries.iter().any(|e| e.api_name == "entry:esm"));
}

#[test]
fn analyze_package_both_cjs_and_esm_entries() {
    let pkg =
        r#"{"name":"dual","version":"1.0.0","main":"dist/index.js","module":"dist/index.mjs"}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.api_entries.iter().any(|e| e.api_name == "entry:cjs"));
    assert!(report.api_entries.iter().any(|e| e.api_name == "entry:esm"));
}

// =========================================================================
// 24. analyze_package — script detection
// =========================================================================

#[test]
fn analyze_package_detects_node_in_scripts() {
    let pkg = r#"{"name":"cli","version":"1.0.0","scripts":{"start":"node server.js"}}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(
        report
            .api_entries
            .iter()
            .any(|e| e.api_name == "runtime:node-cli")
    );
}

#[test]
fn analyze_package_detects_npx_in_scripts() {
    let pkg = r#"{"name":"cli","version":"1.0.0","scripts":{"test":"npx jest"}}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(
        report
            .api_entries
            .iter()
            .any(|e| e.api_name == "runtime:node-cli")
    );
}

#[test]
fn analyze_package_no_node_cli_if_no_scripts() {
    let pkg = r#"{"name":"no-scripts","version":"1.0.0"}"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(
        !report
            .api_entries
            .iter()
            .any(|e| e.api_name == "runtime:node-cli")
    );
}

// =========================================================================
// 25. analyze_package — dependencies disabled
// =========================================================================

#[test]
fn analyze_package_deps_disabled_ignores_all() {
    let config = MigrationConfig {
        analyze_dependencies: false,
        ..MigrationConfig::default()
    };
    let pkg = r#"{"name":"x","version":"1.0.0","dependencies":{"express":"^4","sharp":"^0.33"}}"#;
    let report = analyze_package(pkg, &config).unwrap();
    assert!(report.dependency_entries.is_empty());
}

// =========================================================================
// 26. analyze_package — Bun runtime
// =========================================================================

#[test]
fn analyze_package_bun_runtime_in_report() {
    let config = MigrationConfig {
        source_runtime: SourceRuntime::Bun,
        ..MigrationConfig::default()
    };
    let pkg = r#"{"name":"bun-app","version":"1.0.0"}"#;
    let report = analyze_package(pkg, &config).unwrap();
    assert_eq!(report.source_runtime, SourceRuntime::Bun);
}

// =========================================================================
// 27. generate_manifest — scoped package name transform
// =========================================================================

#[test]
fn manifest_scoped_name_transform() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "@scope/my-pkg".into(),
        source_version: "1.0.0".into(),
        entry_point: "index.js".into(),
        compatibility: empty_compat(),
        behavior: empty_behavior(),
        capabilities: empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();
    assert_eq!(manifest.franken_extension_name, "scope__my-pkg");
}

#[test]
fn manifest_unscoped_name_unchanged() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "simple-pkg".into(),
        source_version: "1.0.0".into(),
        entry_point: "index.js".into(),
        compatibility: empty_compat(),
        behavior: empty_behavior(),
        capabilities: empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();
    assert_eq!(manifest.franken_extension_name, "simple-pkg");
}

// =========================================================================
// 28. generate_manifest — carries capabilities to required_capabilities
// =========================================================================

#[test]
fn manifest_carries_capabilities() {
    let mut caps = empty_caps();
    caps.minimum_capability_set.insert("cap:fs".into());
    caps.minimum_capability_set.insert("cap:net".into());

    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "cap-test".into(),
        source_version: "1.0.0".into(),
        entry_point: "index.js".into(),
        compatibility: empty_compat(),
        behavior: empty_behavior(),
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();
    assert!(manifest.required_capabilities.contains("cap:fs"));
    assert!(manifest.required_capabilities.contains("cap:net"));
}

// =========================================================================
// 29. generate_manifest — deterministic hash
// =========================================================================

#[test]
fn manifest_deterministic_across_calls() {
    let mk = || ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "det".into(),
        source_version: "1.0.0".into(),
        entry_point: "i.js".into(),
        compatibility: empty_compat(),
        behavior: empty_behavior(),
        capabilities: empty_caps(),
        epoch: SecurityEpoch::from_raw(7),
    };
    let m1 = generate_manifest(mk()).unwrap();
    let m2 = generate_manifest(mk()).unwrap();
    assert_eq!(m1.manifest_id, m2.manifest_id);
    assert_eq!(m1.manifest_content_hash, m2.manifest_content_hash);
}

// =========================================================================
// 30. emit_migration_event — valid JSON and field presence
// =========================================================================

#[test]
fn emit_event_produces_valid_json() {
    let event = MigrationEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        component: "migration_kit".into(),
        event: "test".into(),
        outcome: "pass".into(),
        error_code: None,
        details: BTreeMap::new(),
    };
    let json = emit_migration_event(&event);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["trace_id"], "t");
    assert_eq!(parsed["outcome"], "pass");
    assert!(parsed["error_code"].is_null());
}

#[test]
fn emit_event_with_error_code() {
    let event = MigrationEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        component: "migration_kit".into(),
        event: "fail".into(),
        outcome: "failure".into(),
        error_code: Some("FE-MK-0006".into()),
        details: BTreeMap::from([("reason".into(), "parse error".into())]),
    };
    let json = emit_migration_event(&event);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["error_code"], "FE-MK-0006");
    assert_eq!(parsed["details"]["reason"], "parse error");
}

// =========================================================================
// 31. E2E: Bun with capabilities through manifest
// =========================================================================

#[test]
fn e2e_bun_with_capabilities() {
    let config = MigrationConfig {
        source_runtime: SourceRuntime::Bun,
        ..MigrationConfig::default()
    };
    let pkg =
        r#"{"name":"bun-ext","version":"0.5.0","main":"index.ts","dependencies":{"zod":"^3"}}"#;
    let compat = analyze_package(pkg, &config).unwrap();
    assert_eq!(compat.source_runtime, SourceRuntime::Bun);

    let files = vec![SourceFile {
        path: "index.ts".into(),
        content: r#"
            const crypto = require('crypto');
            const port = process.env.PORT;
            setTimeout(() => {}, 1000);
        "#
        .into(),
    }];
    let caps = infer_capabilities(&files, &config).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:crypto"));
    assert!(caps.minimum_capability_set.contains("cap:env"));
    assert!(caps.minimum_capability_set.contains("cap:timer"));

    let results = vec![passing_result("t1"), passing_result("t2")];
    let behavior = validate_behavior(&results, &config).unwrap();
    assert_eq!(behavior.parity_score_millionths, 1_000_000);

    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Bun,
        source_package_name: "bun-ext".into(),
        source_version: "0.5.0".into(),
        entry_point: "index.ts".into(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(3),
    })
    .unwrap();

    assert_eq!(manifest.source_runtime, SourceRuntime::Bun);
    assert!(manifest.required_capabilities.contains("cap:crypto"));
    assert!(manifest.required_capabilities.contains("cap:env"));
    assert!(manifest.required_capabilities.contains("cap:timer"));
    assert!(manifest.migration_readiness_score_millionths >= 900_000);
}

// =========================================================================
// 32. E2E: Package with all incompatible deps → high remediation count
// =========================================================================

#[test]
fn e2e_all_incompatible_produces_remediation_for_each() {
    let pkg = r#"{"name":"bad","version":"1.0.0","dependencies":{
        "express":"^4","sharp":"^0.33","ws":"^8"
    }}"#;
    let compat = analyze_package(pkg, &node_config()).unwrap();
    let behavior = empty_behavior();
    let caps = empty_caps();

    let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
    let dep_swap_count = steps
        .iter()
        .filter(|s| s.category == RemediationCategory::DependencySwap)
        .count();
    assert_eq!(dep_swap_count, 3, "one DependencySwap per incompatible dep");
}

// =========================================================================
// 33. Capability inference — process.spawn pattern
// =========================================================================

#[test]
fn infer_process_spawn() {
    let files = vec![SourceFile {
        path: "run.js".into(),
        content: "process.spawn('cmd')".into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    assert!(
        result
            .inferred_capabilities
            .iter()
            .any(|c| c.kind == InferredCapabilityKind::ProcessSpawn)
    );
    assert!(result.minimum_capability_set.contains("cap:process:spawn"));
}

// =========================================================================
// 34. Capability inference — ESM from syntax variants
// =========================================================================

#[test]
fn infer_esm_fs_single_quotes() {
    let files = vec![SourceFile {
        path: "mod.mjs".into(),
        content: "import fs from 'fs'".into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    assert!(
        result
            .inferred_capabilities
            .iter()
            .any(|c| c.kind == InferredCapabilityKind::FileSystem)
    );
}

#[test]
fn infer_esm_http_double_quotes() {
    let files = vec![SourceFile {
        path: "server.mjs".into(),
        content: r#"import http from "http""#.into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    assert!(
        result
            .inferred_capabilities
            .iter()
            .any(|c| c.kind == InferredCapabilityKind::Network)
    );
}

#[test]
fn infer_require_fs_promises() {
    let files = vec![SourceFile {
        path: "async.js".into(),
        content: r#"const fsp = require("fs/promises")"#.into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    assert!(
        result
            .inferred_capabilities
            .iter()
            .any(|c| c.kind == InferredCapabilityKind::FileSystem)
    );
}

// =========================================================================
// 35. Capability inference — evidence sources tracked
// =========================================================================

#[test]
fn infer_capability_evidence_sources_tracked() {
    let files = vec![
        SourceFile {
            path: "a.js".into(),
            content: "const fs = require('fs');".into(),
        },
        SourceFile {
            path: "b.js".into(),
            content: r#"import { readFile } from "fs""#.into(),
        },
    ];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    let fs_cap = result
        .inferred_capabilities
        .iter()
        .find(|c| c.kind == InferredCapabilityKind::FileSystem)
        .unwrap();
    assert!(fs_cap.evidence_sources.contains(&"a.js".to_string()));
    assert!(fs_cap.evidence_sources.contains(&"b.js".to_string()));
}

// =========================================================================
// 36. Capability inference — sorted by confidence descending
// =========================================================================

#[test]
fn infer_capabilities_sorted_by_confidence_desc() {
    let files = vec![SourceFile {
        path: "all.js".into(),
        content: r#"
            const fs = require('fs');
            const http = require('http');
            process.env.X;
            setTimeout(fn, 100);
        "#
        .into(),
    }];
    let result = infer_capabilities(&files, &node_config()).unwrap();
    for window in result.inferred_capabilities.windows(2) {
        assert!(
            window[0].confidence_millionths >= window[1].confidence_millionths,
            "capabilities should be sorted by confidence descending"
        );
    }
}

// =========================================================================
// 37. analyze_package — report_content_hash deterministic
// =========================================================================

#[test]
fn analyze_package_content_hash_deterministic() {
    let pkg = r#"{"name":"det","version":"1.0.0","dependencies":{"lodash":"^4","express":"^4"}}"#;
    let r1 = analyze_package(pkg, &node_config()).unwrap();
    let r2 = analyze_package(pkg, &node_config()).unwrap();
    assert_eq!(r1.report_content_hash, r2.report_content_hash);
    assert_eq!(
        r1.compatibility_score_millionths,
        r2.compatibility_score_millionths
    );
}

// =========================================================================
// 38. analyze_package — empty package has perfect score
// =========================================================================

#[test]
fn analyze_empty_package_perfect_score() {
    let report = analyze_package(r#"{}"#, &node_config()).unwrap();
    assert_eq!(report.total_apis_used, 0);
    assert_eq!(report.compatibility_score_millionths, 1_000_000);
}

// =========================================================================
// 39. validate_behavior — parity score calculation
// =========================================================================

#[test]
fn validate_behavior_parity_score_fractions() {
    // 3 pass, 1 fail => 3/4 = 750_000
    let results = vec![
        passing_result("t1"),
        passing_result("t2"),
        passing_result("t3"),
        LockstepTestResult {
            test_name: "fail".into(),
            node_output: "a".into(),
            franken_output: "b".into(),
            node_exit_code: 0,
            franken_exit_code: 0,
            node_duration_us: 50,
            franken_duration_us: 50,
        },
    ];
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.parity_score_millionths, 750_000);
}

// =========================================================================
// 40. validate_behavior — divergences sorted by severity
// =========================================================================

#[test]
fn validate_behavior_divergences_sorted_by_severity() {
    let results = vec![
        // Output diff → Medium/Low severity
        LockstepTestResult {
            test_name: "minor".into(),
            node_output: "Hello".into(),
            franken_output: "hello".into(),
            node_exit_code: 0,
            franken_exit_code: 0,
            node_duration_us: 50,
            franken_duration_us: 50,
        },
        // Both differ → Critical
        LockstepTestResult {
            test_name: "critical".into(),
            node_output: "expected".into(),
            franken_output: "crash".into(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 50,
            franken_duration_us: 50,
        },
        // Exit-only → High
        LockstepTestResult {
            test_name: "exit_only".into(),
            node_output: "same".into(),
            franken_output: "same".into(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 50,
            franken_duration_us: 50,
        },
    ];
    let report = validate_behavior(&results, &node_config()).unwrap();
    for window in report.divergences.windows(2) {
        assert!(window[0].severity <= window[1].severity);
    }
}
