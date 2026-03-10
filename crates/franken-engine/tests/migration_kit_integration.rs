//! Integration tests for the migration_kit module (bd-3bz4.2).
//!
//! Tests full migration workflows: package analysis → capability inference →
//! behavior validation → remediation → manifest generation.

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
    ApiSupportLevel, BehaviorDivergence, BehaviorValidationReport, COMPONENT,
    CapabilityInferenceResult, CompatibilityReport, DivergenceKind, DivergenceSeverity,
    InferredCapabilityKind, LockstepTestResult, ManifestGenerationInput, MigrationConfig,
    MigrationEvent, MigrationKitError, REPORT_SCHEMA_DEF, RemediationCategory, RemediationEffort,
    SourceFile, SourceRuntime, analyze_package, compute_migration_readiness, emit_migration_event,
    generate_manifest, generate_remediation, infer_capabilities, lookup_api, validate_behavior,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// =========================================================================
// Helpers
// =========================================================================

fn node_config() -> MigrationConfig {
    MigrationConfig::default()
}

fn bun_config() -> MigrationConfig {
    MigrationConfig {
        source_runtime: SourceRuntime::Bun,
        ..MigrationConfig::default()
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

fn failing_result(name: &str, node_out: &str, franken_out: &str) -> LockstepTestResult {
    LockstepTestResult {
        test_name: name.to_string(),
        node_output: node_out.to_string(),
        franken_output: franken_out.to_string(),
        node_exit_code: 0,
        franken_exit_code: 0,
        node_duration_us: 500,
        franken_duration_us: 600,
    }
}

fn exit_mismatch_result(name: &str) -> LockstepTestResult {
    LockstepTestResult {
        test_name: name.to_string(),
        node_output: "error".to_string(),
        franken_output: "error".to_string(),
        node_exit_code: 0,
        franken_exit_code: 1,
        node_duration_us: 500,
        franken_duration_us: 600,
    }
}

fn make_empty_compat() -> CompatibilityReport {
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
        report_content_hash: ContentHash::compute(b"empty"),
    }
}

fn make_empty_behavior() -> BehaviorValidationReport {
    BehaviorValidationReport {
        total_test_cases: 1,
        passing_count: 1,
        divergence_count: 0,
        parity_score_millionths: 1_000_000,
        divergences: vec![],
        report_content_hash: ContentHash::compute(b"empty"),
    }
}

fn make_empty_caps() -> CapabilityInferenceResult {
    CapabilityInferenceResult {
        inferred_capabilities: vec![],
        minimum_capability_set: BTreeSet::new(),
        recommended_capability_set: BTreeSet::new(),
        capability_hash: ContentHash::compute(b"empty"),
    }
}

// =========================================================================
// E2E: Full migration workflow
// =========================================================================

#[test]
fn test_full_migration_workflow_simple_package() {
    let pkg = r#"{
        "name": "simple-extension",
        "version": "1.0.0",
        "main": "index.js",
        "dependencies": {
            "lodash": "^4.17.21",
            "uuid": "^9.0.0"
        }
    }"#;

    let config = node_config();

    // Step 1: Analyze package
    let compat = analyze_package(pkg, &config).unwrap();
    assert_eq!(compat.source_runtime, SourceRuntime::Node);
    assert!(compat.compatibility_score_millionths > 0);

    // Step 2: Infer capabilities
    let source_files = vec![SourceFile {
        path: "index.js".to_string(),
        content: r#"
            const _ = require('lodash');
            const { v4: uuidv4 } = require('uuid');
            const fs = require('fs');
            module.exports = { process: (data) => _.map(data, x => x + 1) };
        "#
        .to_string(),
    }];
    let caps = infer_capabilities(&source_files, &config).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:fs"));

    // Step 3: Validate behavior
    let test_results = vec![
        passing_result("test_map"),
        passing_result("test_uuid"),
        passing_result("test_fs_read"),
    ];
    let behavior = validate_behavior(&test_results, &config).unwrap();
    assert_eq!(behavior.passing_count, 3);
    assert_eq!(behavior.parity_score_millionths, 1_000_000);

    // Step 4: Generate remediation
    let remediation = generate_remediation(&compat, &behavior, &caps).unwrap();
    // No unsupported APIs or divergences → no steps
    // (lodash, uuid are compatible)

    // Step 5: Generate manifest
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "simple-extension".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();

    assert_eq!(manifest.source_package_name, "simple-extension");
    assert_eq!(manifest.franken_extension_name, "simple-extension");
    assert!(manifest.migration_readiness_score_millionths >= 900_000);
    assert!(manifest.required_capabilities.contains("cap:fs"));

    // Step 6: Emit event
    let event = MigrationEvent {
        trace_id: "e2e-001".to_string(),
        decision_id: "d-001".to_string(),
        component: "migration_kit".to_string(),
        event: "workflow_complete".to_string(),
        outcome: "success".to_string(),
        error_code: None,
        details: BTreeMap::from([
            (
                "readiness".to_string(),
                manifest.migration_readiness_score_millionths.to_string(),
            ),
            (
                "remediation_count".to_string(),
                remediation.len().to_string(),
            ),
        ]),
    };
    let json = emit_migration_event(&event);
    assert!(json.contains("e2e-001"));
    assert!(json.contains("workflow_complete"));
}

#[test]
fn test_full_migration_workflow_complex_package() {
    let pkg = r#"{
        "name": "@myorg/server-extension",
        "version": "3.2.1",
        "main": "dist/index.js",
        "module": "dist/index.mjs",
        "dependencies": {
            "express": "^4.18.0",
            "axios": "^1.5.0",
            "lodash": "^4.17.21",
            "sharp": "^0.33.0",
            "zod": "^3.22.0",
            "pg": "^8.11.0",
            "redis": "^4.6.0"
        },
        "devDependencies": {
            "typescript": "^5.3.0",
            "jest": "^29.7.0"
        },
        "scripts": {
            "start": "node dist/index.js",
            "test": "jest"
        }
    }"#;

    let config = node_config();
    let compat = analyze_package(pkg, &config).unwrap();

    // Should detect incompatible deps
    let incompatible: Vec<_> = compat
        .dependency_entries
        .iter()
        .filter(|d| !d.compatible)
        .collect();
    assert!(incompatible.len() >= 4); // express, axios, sharp, pg, redis

    // Analyze source
    let files = vec![
        SourceFile {
            path: "src/server.ts".to_string(),
            content: r#"
                import express from 'express';
                import { createHash } from 'crypto';
                const http = require('http');
                const port = process.env.PORT || 3000;
            "#
            .to_string(),
        },
        SourceFile {
            path: "src/db.ts".to_string(),
            content: "import { Pool } from 'pg';\nimport { createClient } from 'redis';"
                .to_string(),
        },
    ];
    let caps = infer_capabilities(&files, &config).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:net"));
    assert!(caps.minimum_capability_set.contains("cap:crypto"));
    assert!(caps.minimum_capability_set.contains("cap:env"));

    // Behavior with divergences
    let results = vec![
        passing_result("unit-lodash"),
        passing_result("unit-zod"),
        failing_result("integration-express", "HTTP 200 OK", "connection refused"),
        failing_result("integration-pg", "rows: [{id: 1}]", "driver not available"),
        exit_mismatch_result("integration-redis"),
    ];
    let behavior = validate_behavior(&results, &config).unwrap();
    assert_eq!(behavior.passing_count, 2);
    assert_eq!(behavior.divergence_count, 3);
    assert!(behavior.parity_score_millionths < 500_000);

    // Generate remediation
    let remediation = generate_remediation(&compat, &behavior, &caps).unwrap();
    assert!(!remediation.is_empty());

    // Generate manifest
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "@myorg/server-extension".to_string(),
        source_version: "3.2.1".to_string(),
        entry_point: "dist/index.js".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(10),
    })
    .unwrap();

    assert_eq!(manifest.franken_extension_name, "myorg__server-extension");
    assert!(manifest.migration_readiness_score_millionths < 800_000);
}

// =========================================================================
// Bun runtime workflow
// =========================================================================

#[test]
fn test_bun_migration_workflow() {
    let pkg = r#"{
        "name": "bun-tool",
        "version": "0.1.0",
        "main": "index.ts",
        "dependencies": {
            "chalk": "^5.0.0",
            "commander": "^11.0.0"
        }
    }"#;

    let config = bun_config();
    let compat = analyze_package(pkg, &config).unwrap();
    assert_eq!(compat.source_runtime, SourceRuntime::Bun);

    let files = vec![SourceFile {
        path: "index.ts".to_string(),
        content: "import chalk from 'chalk';\nconsole.log(chalk.green('hello'));".to_string(),
    }];
    let caps = infer_capabilities(&files, &config).unwrap();

    let results = vec![passing_result("cli-output"), passing_result("cli-help")];
    let behavior = validate_behavior(&results, &config).unwrap();
    assert_eq!(behavior.parity_score_millionths, 1_000_000);

    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Bun,
        source_package_name: "bun-tool".to_string(),
        source_version: "0.1.0".to_string(),
        entry_point: "index.ts".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();

    assert_eq!(manifest.source_runtime, SourceRuntime::Bun);
}

// =========================================================================
// Determinism tests
// =========================================================================

#[test]
fn test_full_workflow_deterministic() {
    let pkg = r#"{"name":"det-test","version":"1.0.0","dependencies":{"lodash":"^4.0.0","express":"^4.0.0"}}"#;
    let config = node_config();

    let compat1 = analyze_package(pkg, &config).unwrap();
    let compat2 = analyze_package(pkg, &config).unwrap();
    assert_eq!(compat1.report_content_hash, compat2.report_content_hash);
    assert_eq!(
        compat1.compatibility_score_millionths,
        compat2.compatibility_score_millionths
    );

    let files = vec![SourceFile {
        path: "a.js".to_string(),
        content: "const fs = require('fs'); const http = require('http');".to_string(),
    }];
    let caps1 = infer_capabilities(&files, &config).unwrap();
    let caps2 = infer_capabilities(&files, &config).unwrap();
    assert_eq!(caps1.capability_hash, caps2.capability_hash);

    let results = vec![passing_result("t1"), failing_result("t2", "a", "b")];
    let beh1 = validate_behavior(&results, &config).unwrap();
    let beh2 = validate_behavior(&results, &config).unwrap();
    assert_eq!(beh1.report_content_hash, beh2.report_content_hash);
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn test_unicode_content_in_source_files() {
    let files = vec![SourceFile {
        path: "unicode.js".to_string(),
        content: "const fs = require('fs');\n// 日本語コメント\nconst x = '🎉';".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:fs"));
}

#[test]
fn test_empty_source_files() {
    let files: Vec<SourceFile> = vec![];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.is_empty());
    assert!(caps.inferred_capabilities.is_empty());
}

#[test]
fn test_large_number_of_test_results() {
    let results: Vec<LockstepTestResult> = (0..500)
        .map(|i| passing_result(&format!("test_{i}")))
        .collect();
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.passing_count, 500);
    assert_eq!(report.parity_score_millionths, 1_000_000);
}

#[test]
fn test_mixed_divergence_severities() {
    let results = vec![
        passing_result("pass"),
        failing_result("case-diff", "Hello", "hello"),
        failing_result("major-diff", "long output with lots of content", "x"),
        LockstepTestResult {
            test_name: "exit-diff".to_string(),
            node_output: "error".to_string(),
            franken_output: "different-error".to_string(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 100,
            franken_duration_us: 100,
        },
    ];
    let report = validate_behavior(&results, &node_config()).unwrap();
    assert_eq!(report.passing_count, 1);
    assert_eq!(report.divergence_count, 3);

    let severities: Vec<_> = report.divergences.iter().map(|d| d.severity).collect();
    // Should be sorted by severity
    for window in severities.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

// =========================================================================
// Error handling
// =========================================================================

#[test]
fn test_invalid_json_package() {
    let err = analyze_package("}{bad json", &node_config()).unwrap_err();
    assert!(matches!(err, MigrationKitError::InvalidPackageJson { .. }));
    assert_eq!(err.code(), "FE-MK-0006");
}

#[test]
fn test_empty_test_results() {
    let err = validate_behavior(&[], &node_config()).unwrap_err();
    assert!(matches!(
        err,
        MigrationKitError::BehaviorValidationFailed { .. }
    ));
}

#[test]
fn test_manifest_empty_name() {
    let err = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: String::new(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: make_empty_compat(),
        behavior: make_empty_behavior(),
        capabilities: make_empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap_err();
    assert_eq!(err.code(), "FE-MK-0002");
}

// =========================================================================
// Readiness score
// =========================================================================

#[test]
fn test_readiness_score_boundaries() {
    // Perfect scores
    let compat = CompatibilityReport {
        source_runtime: SourceRuntime::Node,
        total_apis_used: 10,
        fully_supported_count: 10,
        partially_supported_count: 0,
        unsupported_count: 0,
        deprecated_count: 0,
        polyfill_required_count: 0,
        compatibility_score_millionths: 1_000_000,
        api_entries: vec![],
        dependency_entries: vec![],
        report_content_hash: ContentHash::compute(b"test"),
    };
    let behavior = BehaviorValidationReport {
        total_test_cases: 100,
        passing_count: 100,
        divergence_count: 0,
        parity_score_millionths: 1_000_000,
        divergences: vec![],
        report_content_hash: ContentHash::compute(b"test"),
    };
    assert_eq!(compute_migration_readiness(&compat, &behavior), 1_000_000);

    // Zero compatibility, perfect parity
    let compat_zero = CompatibilityReport {
        compatibility_score_millionths: 0,
        ..compat.clone()
    };
    assert_eq!(
        compute_migration_readiness(&compat_zero, &behavior),
        600_000
    );

    // Perfect compatibility, zero parity
    let behavior_zero = BehaviorValidationReport {
        parity_score_millionths: 0,
        ..behavior.clone()
    };
    assert_eq!(
        compute_migration_readiness(&compat, &behavior_zero),
        400_000
    );

    // Both zero
    assert_eq!(compute_migration_readiness(&compat_zero, &behavior_zero), 0);
}

// =========================================================================
// Package.json edge cases
// =========================================================================

#[test]
fn test_package_with_only_dev_dependencies() {
    let pkg = r#"{
        "name": "dev-only",
        "version": "1.0.0",
        "devDependencies": {
            "typescript": "^5.3.0",
            "vitest": "^1.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.dependency_entries.iter().all(|d| d.compatible));
}

#[test]
fn test_package_with_peer_dependencies() {
    let pkg = r#"{
        "name": "peer-pkg",
        "version": "1.0.0",
        "peerDependencies": {
            "react": "^18.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert_eq!(report.dependency_entries.len(), 1);
}

#[test]
fn test_package_with_all_compatible_deps() {
    let pkg = r#"{
        "name": "all-compat",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.0.0",
            "uuid": "^9.0.0",
            "chalk": "^5.0.0",
            "zod": "^3.22.0",
            "date-fns": "^3.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    assert!(report.dependency_entries.iter().all(|d| d.compatible));
    assert!(report.compatibility_score_millionths >= 900_000);
}

#[test]
fn test_package_with_all_incompatible_deps() {
    let pkg = r#"{
        "name": "all-incompat",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.0.0",
            "sharp": "^0.33.0",
            "sqlite3": "^5.0.0",
            "ws": "^8.0.0",
            "pg": "^8.0.0"
        }
    }"#;
    let report = analyze_package(pkg, &node_config()).unwrap();
    let incompatible_count = report
        .dependency_entries
        .iter()
        .filter(|d| !d.compatible)
        .count();
    assert_eq!(incompatible_count, 5);
}

// =========================================================================
// Capability inference edge cases
// =========================================================================

#[test]
fn test_infer_esm_import_syntax() {
    let files = vec![SourceFile {
        path: "esm.mjs".to_string(),
        content: "import { readFile } from 'fs';\nimport { createServer } from 'http';".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:fs"));
    assert!(caps.minimum_capability_set.contains("cap:net"));
}

#[test]
fn test_infer_dynamic_import() {
    let files = vec![SourceFile {
        path: "dynamic.js".to_string(),
        content: "const mod = await import('./plugin.js');".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:import:dynamic"));
}

#[test]
fn test_infer_native_addon() {
    let files = vec![SourceFile {
        path: "binding.js".to_string(),
        content: "const binding = require('./build/Release/addon.node\");".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:native-addon"));
}

// =========================================================================
// Remediation quality
// =========================================================================

#[test]
fn test_remediation_sorted_by_priority() {
    let compat = analyze_package(
        r#"{"name":"x","version":"1.0.0","dependencies":{"express":"^4.0.0","sharp":"^0.33.0"}}"#,
        &node_config(),
    )
    .unwrap();
    let behavior = make_empty_behavior();
    let caps = make_empty_caps();

    let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
    // Should be sorted descending by priority
    for window in steps.windows(2) {
        assert!(window[0].priority_score_millionths >= window[1].priority_score_millionths);
    }
}

#[test]
fn test_remediation_has_behavior_fixes() {
    let compat = make_empty_compat();
    let schema_id =
        frankenengine_engine::engine_object_id::SchemaId::from_definition(b"BehaviorDivergence.v1");
    let div_id = frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::EvidenceRecord,
        "migration-kit",
        &schema_id,
        b"test-div",
    )
    .unwrap();

    let behavior = BehaviorValidationReport {
        total_test_cases: 2,
        passing_count: 1,
        divergence_count: 1,
        parity_score_millionths: 500_000,
        divergences: vec![BehaviorDivergence {
            divergence_id: div_id,
            kind: DivergenceKind::SemanticDifference,
            severity: DivergenceSeverity::Critical,
            test_case: "critical-test".to_string(),
            node_bun_result: "expected".to_string(),
            franken_result: "different".to_string(),
            explanation: "semantic mismatch".to_string(),
            remediation: "fix logic".to_string(),
        }],
        report_content_hash: ContentHash::compute(b"test"),
    };
    let caps = make_empty_caps();

    let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
    assert!(!steps.is_empty());
    assert!(steps.iter().any(|s| s.title.contains("critical-test")));
}

// =========================================================================
// Manifest content hashing
// =========================================================================

#[test]
fn test_manifest_content_hash_stable() {
    let compat = make_empty_compat();
    let behavior = make_empty_behavior();
    let caps = make_empty_caps();

    let m1 = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "hash-test".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: compat.clone(),
        behavior: behavior.clone(),
        capabilities: caps.clone(),
        epoch: SecurityEpoch::from_raw(42),
    })
    .unwrap();

    let m2 = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "hash-test".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: compat,
        behavior,
        capabilities: caps,
        epoch: SecurityEpoch::from_raw(42),
    })
    .unwrap();

    assert_eq!(m1.manifest_content_hash, m2.manifest_content_hash);
    assert_eq!(m1.manifest_id, m2.manifest_id);
}

// =========================================================================
// Event emission
// =========================================================================

#[test]
fn test_event_roundtrip() {
    let event = MigrationEvent {
        trace_id: "tr-integration".to_string(),
        decision_id: "d-integration".to_string(),
        component: "migration_kit".to_string(),
        event: "test_event".to_string(),
        outcome: "success".to_string(),
        error_code: None,
        details: BTreeMap::from([
            ("key1".to_string(), "value1".to_string()),
            ("key2".to_string(), "value2".to_string()),
        ]),
    };
    let json = emit_migration_event(&event);
    let parsed: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.trace_id, "tr-integration");
    assert_eq!(parsed.details.len(), 2);
}

// =========================================================================
// Serde roundtrip for complex types
// =========================================================================

#[test]
fn test_serde_roundtrip_manifest() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "serde-test".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: make_empty_compat(),
        behavior: make_empty_behavior(),
        capabilities: make_empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();

    let json = serde_json::to_string(&manifest).unwrap();
    let roundtripped: frankenengine_engine::migration_kit::MigrationManifest =
        serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.manifest_id, roundtripped.manifest_id);
    assert_eq!(
        manifest.source_package_name,
        roundtripped.source_package_name
    );
}

#[test]
fn test_serde_roundtrip_behavior_report() {
    let results = vec![passing_result("t1"), failing_result("t2", "a", "b")];
    let report = validate_behavior(&results, &node_config()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let roundtripped: BehaviorValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.passing_count, roundtripped.passing_count);
    assert_eq!(report.divergence_count, roundtripped.divergence_count);
}

// =========================================================================
// Enum serde round-trips
// =========================================================================

#[test]
fn test_serde_roundtrip_source_runtime() {
    for rt in [SourceRuntime::Node, SourceRuntime::Bun] {
        let json = serde_json::to_string(&rt).unwrap();
        let back: SourceRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, back);
    }
}

#[test]
fn test_serde_roundtrip_api_support_level() {
    let variants = [
        ApiSupportLevel::FullySupported,
        ApiSupportLevel::PartiallySupported,
        ApiSupportLevel::Unsupported,
        ApiSupportLevel::Deprecated,
        ApiSupportLevel::RequiresPolyfill,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: ApiSupportLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_serde_roundtrip_divergence_kind() {
    let variants = [
        DivergenceKind::SemanticDifference,
        DivergenceKind::TimingDifference,
        DivergenceKind::OutputFormatDifference,
        DivergenceKind::ErrorBehaviorDifference,
        DivergenceKind::MissingFeature,
        DivergenceKind::SecurityPolicyDifference,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: DivergenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_serde_roundtrip_divergence_severity() {
    let variants = [
        DivergenceSeverity::Critical,
        DivergenceSeverity::High,
        DivergenceSeverity::Medium,
        DivergenceSeverity::Low,
        DivergenceSeverity::Informational,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: DivergenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_serde_roundtrip_inferred_capability_kind() {
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
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: InferredCapabilityKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_serde_roundtrip_remediation_category() {
    let variants = [
        RemediationCategory::ApiReplacement,
        RemediationCategory::DependencySwap,
        RemediationCategory::ConfigChange,
        RemediationCategory::CodeRefactor,
        RemediationCategory::PolyfillAddition,
        RemediationCategory::SecurityPolicyUpdate,
        RemediationCategory::FeatureDisable,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: RemediationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn test_serde_roundtrip_remediation_effort() {
    let variants = [
        RemediationEffort::Trivial,
        RemediationEffort::Low,
        RemediationEffort::Medium,
        RemediationEffort::High,
        RemediationEffort::Significant,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: RemediationEffort = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// =========================================================================
// Constants stability
// =========================================================================

#[test]
fn test_component_constant() {
    assert_eq!(COMPONENT, "migration_kit");
}

#[test]
fn test_report_schema_def_constant() {
    assert_eq!(REPORT_SCHEMA_DEF, b"MigrationAnalysisReport.v1");
}

// =========================================================================
// Display implementations
// =========================================================================

#[test]
fn test_source_runtime_display() {
    assert_eq!(format!("{}", SourceRuntime::Node), "Node.js");
    assert_eq!(format!("{}", SourceRuntime::Bun), "Bun");
}

// =========================================================================
// ApiSupportLevel methods
// =========================================================================

#[test]
fn test_api_support_level_is_migration_blocker() {
    assert!(ApiSupportLevel::Unsupported.is_migration_blocker());
    assert!(!ApiSupportLevel::FullySupported.is_migration_blocker());
    assert!(!ApiSupportLevel::PartiallySupported.is_migration_blocker());
    assert!(!ApiSupportLevel::Deprecated.is_migration_blocker());
    assert!(!ApiSupportLevel::RequiresPolyfill.is_migration_blocker());
}

#[test]
fn test_api_support_level_compatibility_weight() {
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

#[test]
fn test_api_support_level_weight_ordering() {
    // Weights should decrease: FullySupported > Partial > Deprecated > Polyfill > Unsupported
    let weights: Vec<u64> = [
        ApiSupportLevel::FullySupported,
        ApiSupportLevel::PartiallySupported,
        ApiSupportLevel::Deprecated,
        ApiSupportLevel::RequiresPolyfill,
        ApiSupportLevel::Unsupported,
    ]
    .iter()
    .map(|l| l.compatibility_weight_millionths())
    .collect();
    for window in weights.windows(2) {
        assert!(window[0] > window[1]);
    }
}

// =========================================================================
// DivergenceSeverity methods
// =========================================================================

#[test]
fn test_divergence_severity_penalty() {
    assert_eq!(DivergenceSeverity::Critical.penalty_millionths(), 200_000);
    assert_eq!(DivergenceSeverity::High.penalty_millionths(), 100_000);
    assert_eq!(DivergenceSeverity::Medium.penalty_millionths(), 50_000);
    assert_eq!(DivergenceSeverity::Low.penalty_millionths(), 20_000);
    assert_eq!(DivergenceSeverity::Informational.penalty_millionths(), 0);
}

#[test]
fn test_divergence_severity_penalty_ordering() {
    // Penalty should decrease: Critical > High > Medium > Low > Informational
    let penalties: Vec<u64> = [
        DivergenceSeverity::Critical,
        DivergenceSeverity::High,
        DivergenceSeverity::Medium,
        DivergenceSeverity::Low,
    ]
    .iter()
    .map(|s| s.penalty_millionths())
    .collect();
    for window in penalties.windows(2) {
        assert!(window[0] > window[1]);
    }
}

// =========================================================================
// InferredCapabilityKind methods
// =========================================================================

#[test]
fn test_inferred_capability_kind_franken_names() {
    assert_eq!(
        InferredCapabilityKind::FileSystem.franken_capability_name(),
        "cap:fs"
    );
    assert_eq!(
        InferredCapabilityKind::Network.franken_capability_name(),
        "cap:net"
    );
    assert_eq!(
        InferredCapabilityKind::ProcessSpawn.franken_capability_name(),
        "cap:process:spawn"
    );
    assert_eq!(
        InferredCapabilityKind::EnvironmentAccess.franken_capability_name(),
        "cap:env"
    );
    assert_eq!(
        InferredCapabilityKind::CryptoAccess.franken_capability_name(),
        "cap:crypto"
    );
    assert_eq!(
        InferredCapabilityKind::TimerAccess.franken_capability_name(),
        "cap:timer"
    );
    assert_eq!(
        InferredCapabilityKind::WorkerThreads.franken_capability_name(),
        "cap:worker"
    );
    assert_eq!(
        InferredCapabilityKind::ChildProcess.franken_capability_name(),
        "cap:process:child"
    );
    assert_eq!(
        InferredCapabilityKind::DynamicImport.franken_capability_name(),
        "cap:import:dynamic"
    );
    assert_eq!(
        InferredCapabilityKind::WasmExecution.franken_capability_name(),
        "cap:wasm"
    );
    assert_eq!(
        InferredCapabilityKind::SharedMemory.franken_capability_name(),
        "cap:shared-memory"
    );
    assert_eq!(
        InferredCapabilityKind::NativeAddon.franken_capability_name(),
        "cap:native-addon"
    );
}

#[test]
fn test_inferred_capability_kind_all_names_distinct() {
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
    let names: BTreeSet<&str> = kinds.iter().map(|k| k.franken_capability_name()).collect();
    assert_eq!(names.len(), kinds.len());
}

#[test]
fn test_inferred_capability_kind_all_start_with_cap() {
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
    for kind in &kinds {
        assert!(
            kind.franken_capability_name().starts_with("cap:"),
            "{:?} name does not start with cap:",
            kind
        );
    }
}

// =========================================================================
// RemediationEffort methods
// =========================================================================

#[test]
fn test_remediation_effort_weight() {
    assert_eq!(RemediationEffort::Trivial.weight_millionths(), 100_000);
    assert_eq!(RemediationEffort::Low.weight_millionths(), 300_000);
    assert_eq!(RemediationEffort::Medium.weight_millionths(), 500_000);
    assert_eq!(RemediationEffort::High.weight_millionths(), 800_000);
    assert_eq!(
        RemediationEffort::Significant.weight_millionths(),
        1_000_000
    );
}

#[test]
fn test_remediation_effort_weight_ordering() {
    // Weight should increase: Trivial < Low < Medium < High < Significant
    let weights: Vec<u64> = [
        RemediationEffort::Trivial,
        RemediationEffort::Low,
        RemediationEffort::Medium,
        RemediationEffort::High,
        RemediationEffort::Significant,
    ]
    .iter()
    .map(|e| e.weight_millionths())
    .collect();
    for window in weights.windows(2) {
        assert!(window[0] < window[1]);
    }
}

// =========================================================================
// lookup_api
// =========================================================================

#[test]
fn test_lookup_api_known_fs_read_file() {
    let api = lookup_api("fs", "readFile");
    assert!(api.is_some());
    let api = api.unwrap();
    assert_eq!(api.module_name, "fs");
    assert_eq!(api.api_name, "readFile");
    assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
}

#[test]
fn test_lookup_api_unknown_returns_none() {
    assert!(lookup_api("nonexistent_module", "nonexistent_api").is_none());
}

#[test]
fn test_lookup_api_wrong_api_name_returns_none() {
    // "fs" module exists, but "fakeFunction" does not
    assert!(lookup_api("fs", "fakeFunction").is_none());
}

// =========================================================================
// Error codes coverage
// =========================================================================

#[test]
fn test_error_code_all_variants() {
    let errors = [
        (
            MigrationKitError::AnalysisFailed { detail: "x".into() },
            "FE-MK-0001",
        ),
        (
            MigrationKitError::ManifestGenerationFailed { detail: "x".into() },
            "FE-MK-0002",
        ),
        (
            MigrationKitError::CapabilityInferenceFailed { detail: "x".into() },
            "FE-MK-0003",
        ),
        (
            MigrationKitError::BehaviorValidationFailed { detail: "x".into() },
            "FE-MK-0004",
        ),
        (
            MigrationKitError::RemediationUnavailable { detail: "x".into() },
            "FE-MK-0005",
        ),
        (
            MigrationKitError::InvalidPackageJson { detail: "x".into() },
            "FE-MK-0006",
        ),
        (
            MigrationKitError::UnsupportedApiDetected {
                api: "a".into(),
                detail: "x".into(),
            },
            "FE-MK-0007",
        ),
        (
            MigrationKitError::IncompatibleDependency {
                name: "n".into(),
                reason: "r".into(),
            },
            "FE-MK-0008",
        ),
        (
            MigrationKitError::LockstepMismatch {
                runtime: "rt".into(),
                detail: "x".into(),
            },
            "FE-MK-0009",
        ),
        (
            MigrationKitError::ReportGenerationFailed { detail: "x".into() },
            "FE-MK-0010",
        ),
        (
            MigrationKitError::DeterminismViolation { detail: "x".into() },
            "FE-MK-0011",
        ),
        (
            MigrationKitError::TooManyEntries {
                kind: "k".into(),
                count: 10,
                max: 5,
            },
            "FE-MK-0012",
        ),
        (
            MigrationKitError::InternalError { detail: "x".into() },
            "FE-MK-0099",
        ),
    ];
    for (err, expected_code) in &errors {
        assert_eq!(err.code(), *expected_code, "code mismatch for {:?}", err);
    }
}

#[test]
fn test_error_display_all_variants_non_empty() {
    let errors = [
        MigrationKitError::AnalysisFailed { detail: "d".into() },
        MigrationKitError::ManifestGenerationFailed { detail: "d".into() },
        MigrationKitError::CapabilityInferenceFailed { detail: "d".into() },
        MigrationKitError::BehaviorValidationFailed { detail: "d".into() },
        MigrationKitError::RemediationUnavailable { detail: "d".into() },
        MigrationKitError::InvalidPackageJson { detail: "d".into() },
        MigrationKitError::UnsupportedApiDetected {
            api: "a".into(),
            detail: "d".into(),
        },
        MigrationKitError::IncompatibleDependency {
            name: "n".into(),
            reason: "r".into(),
        },
        MigrationKitError::LockstepMismatch {
            runtime: "rt".into(),
            detail: "d".into(),
        },
        MigrationKitError::ReportGenerationFailed { detail: "d".into() },
        MigrationKitError::DeterminismViolation { detail: "d".into() },
        MigrationKitError::TooManyEntries {
            kind: "k".into(),
            count: 10,
            max: 5,
        },
        MigrationKitError::InternalError { detail: "d".into() },
    ];
    for err in &errors {
        let msg = format!("{err}");
        assert!(!msg.is_empty(), "empty display for {:?}", err);
    }
}

#[test]
fn test_error_std_error_trait() {
    let err = MigrationKitError::AnalysisFailed {
        detail: "test".into(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(dyn_err.source().is_none());
}

#[test]
fn test_error_serde_roundtrip() {
    let errors = [
        MigrationKitError::AnalysisFailed { detail: "d".into() },
        MigrationKitError::UnsupportedApiDetected {
            api: "a".into(),
            detail: "d".into(),
        },
        MigrationKitError::TooManyEntries {
            kind: "k".into(),
            count: 10,
            max: 5,
        },
        MigrationKitError::InternalError { detail: "d".into() },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: MigrationKitError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// =========================================================================
// Serde roundtrip for additional structs
// =========================================================================

#[test]
fn test_serde_roundtrip_migration_config() {
    let config = MigrationConfig {
        source_runtime: SourceRuntime::Bun,
        analyze_dependencies: false,
        infer_capabilities: true,
        run_behavior_validation: false,
        min_compatibility_score_millionths: 500_000,
        max_divergence_count: 50,
        deterministic_seed: 123,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: MigrationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn test_serde_roundtrip_compatibility_report() {
    let report = make_empty_compat();
    let json = serde_json::to_string(&report).unwrap();
    let back: CompatibilityReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn test_serde_roundtrip_capability_inference_result() {
    let caps = make_empty_caps();
    let json = serde_json::to_string(&caps).unwrap();
    let back: CapabilityInferenceResult = serde_json::from_str(&json).unwrap();
    assert_eq!(caps, back);
}

#[test]
fn test_serde_roundtrip_lockstep_test_result() {
    let result = passing_result("serde_test");
    let json = serde_json::to_string(&result).unwrap();
    let back: LockstepTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn test_serde_roundtrip_source_file() {
    let sf = SourceFile {
        path: "test.js".to_string(),
        content: "console.log('hi');".to_string(),
    };
    let json = serde_json::to_string(&sf).unwrap();
    let back: SourceFile = serde_json::from_str(&json).unwrap();
    assert_eq!(sf, back);
}

#[test]
fn test_serde_roundtrip_migration_event() {
    let event = MigrationEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        component: COMPONENT.to_string(),
        event: "test".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("FE-MK-0001".to_string()),
        details: BTreeMap::from([("k".to_string(), "v".to_string())]),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// =========================================================================
// Enum ordering
// =========================================================================

#[test]
fn test_divergence_severity_ordering() {
    assert!(DivergenceSeverity::Critical < DivergenceSeverity::High);
    assert!(DivergenceSeverity::High < DivergenceSeverity::Medium);
    assert!(DivergenceSeverity::Medium < DivergenceSeverity::Low);
    assert!(DivergenceSeverity::Low < DivergenceSeverity::Informational);
}

#[test]
fn test_api_support_level_ordering() {
    assert!(ApiSupportLevel::FullySupported < ApiSupportLevel::PartiallySupported);
    assert!(ApiSupportLevel::PartiallySupported < ApiSupportLevel::Unsupported);
    assert!(ApiSupportLevel::Unsupported < ApiSupportLevel::Deprecated);
    assert!(ApiSupportLevel::Deprecated < ApiSupportLevel::RequiresPolyfill);
}

// =========================================================================
// compute_migration_readiness additional
// =========================================================================

#[test]
fn test_readiness_score_midpoint() {
    let compat = CompatibilityReport {
        compatibility_score_millionths: 500_000,
        ..make_empty_compat()
    };
    let behavior = BehaviorValidationReport {
        parity_score_millionths: 500_000,
        ..make_empty_behavior()
    };
    let score = compute_migration_readiness(&compat, &behavior);
    assert_eq!(score, 500_000);
}

// =========================================================================
// Event emission edge cases
// =========================================================================

#[test]
fn test_event_with_error_code() {
    let event = MigrationEvent {
        trace_id: "err-trace".to_string(),
        decision_id: "err-dec".to_string(),
        component: COMPONENT.to_string(),
        event: "migration_failed".to_string(),
        outcome: "failure".to_string(),
        error_code: Some("FE-MK-0006".to_string()),
        details: BTreeMap::new(),
    };
    let json = emit_migration_event(&event);
    assert!(json.contains("FE-MK-0006"));
    assert!(json.contains("migration_failed"));
}

#[test]
fn test_event_empty_details() {
    let event = MigrationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        component: COMPONENT.to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
        details: BTreeMap::new(),
    };
    let json = emit_migration_event(&event);
    let parsed: MigrationEvent = serde_json::from_str(&json).unwrap();
    assert!(parsed.details.is_empty());
}

// =========================================================================
// Manifest edge cases
// =========================================================================

#[test]
fn test_manifest_empty_version_accepted() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "test".to_string(),
        source_version: String::new(),
        entry_point: "index.js".to_string(),
        compatibility: make_empty_compat(),
        behavior: make_empty_behavior(),
        capabilities: make_empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();
    assert_eq!(manifest.source_version, "");
}

#[test]
fn test_manifest_empty_entry_point_accepted() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "test".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: String::new(),
        compatibility: make_empty_compat(),
        behavior: make_empty_behavior(),
        capabilities: make_empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();
    assert_eq!(manifest.entry_point, "");
}

#[test]
fn test_manifest_scoped_package_name_normalization() {
    let manifest = generate_manifest(ManifestGenerationInput {
        source_runtime: SourceRuntime::Node,
        source_package_name: "@scope/my-pkg".to_string(),
        source_version: "1.0.0".to_string(),
        entry_point: "index.js".to_string(),
        compatibility: make_empty_compat(),
        behavior: make_empty_behavior(),
        capabilities: make_empty_caps(),
        epoch: SecurityEpoch::from_raw(1),
    })
    .unwrap();
    // Scoped names get @ and / stripped/replaced
    assert!(!manifest.franken_extension_name.contains('@'));
    assert!(!manifest.franken_extension_name.contains('/'));
}

// =========================================================================
// Capability inference patterns
// =========================================================================

#[test]
fn test_infer_crypto_capability() {
    let files = vec![SourceFile {
        path: "hash.js".to_string(),
        content: "const crypto = require('crypto');\nconst hash = crypto.createHash('sha256');"
            .to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:crypto"));
}

#[test]
fn test_infer_env_access_capability() {
    let files = vec![SourceFile {
        path: "config.js".to_string(),
        content: "const port = process.env.PORT || 3000;".to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:env"));
}

#[test]
fn test_infer_multiple_capabilities_single_file() {
    let files = vec![SourceFile {
        path: "app.js".to_string(),
        content: r#"
            const fs = require('fs');
            const http = require('http');
            const crypto = require('crypto');
            const port = process.env.PORT;
        "#
        .to_string(),
    }];
    let caps = infer_capabilities(&files, &node_config()).unwrap();
    assert!(caps.minimum_capability_set.contains("cap:fs"));
    assert!(caps.minimum_capability_set.contains("cap:net"));
    assert!(caps.minimum_capability_set.contains("cap:crypto"));
    assert!(caps.minimum_capability_set.contains("cap:env"));
}
