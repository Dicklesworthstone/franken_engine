#![forbid(unsafe_code)]

//! Integration tests for React ecosystem compatibility validation.

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

use frankenengine_engine::react_compile_verification::CompileMode;
use frankenengine_engine::react_ecosystem_compatibility::*;
use frankenengine_engine::react_package_cohort::{ExportCondition, ReactPackage};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// EcosystemMode integration tests
// ---------------------------------------------------------------------------

#[test]
fn ecosystem_mode_all_variants_covered() {
    let all_modes = EcosystemMode::ALL;
    assert_eq!(all_modes.len(), 4);

    // Verify all expected modes are present
    assert!(all_modes.contains(&EcosystemMode::ServerSideRendering));
    assert!(all_modes.contains(&EcosystemMode::ClientSideRendering));
    assert!(all_modes.contains(&EcosystemMode::StaticSiteGeneration));
    assert!(all_modes.contains(&EcosystemMode::HybridRendering));

    // Verify ordering is deterministic
    let mut sorted = all_modes.to_vec();
    sorted.sort();
    assert_eq!(&sorted, all_modes);
}

#[test]
fn ecosystem_mode_server_capabilities_logic() {
    // SSR modes require server capabilities
    assert!(EcosystemMode::ServerSideRendering.requires_server_capabilities());
    assert!(EcosystemMode::StaticSiteGeneration.requires_server_capabilities());
    assert!(EcosystemMode::HybridRendering.requires_server_capabilities());

    // CSR does not
    assert!(!EcosystemMode::ClientSideRendering.requires_server_capabilities());
}

#[test]
fn ecosystem_mode_client_hydration_logic() {
    // Only hybrid requires client hydration
    assert!(EcosystemMode::HybridRendering.requires_client_hydration());

    // Others do not
    assert!(!EcosystemMode::ServerSideRendering.requires_client_hydration());
    assert!(!EcosystemMode::ClientSideRendering.requires_client_hydration());
    assert!(!EcosystemMode::StaticSiteGeneration.requires_client_hydration());
}

#[test]
fn ecosystem_mode_string_conversion() {
    assert_eq!(EcosystemMode::ServerSideRendering.as_str(), "ssr");
    assert_eq!(EcosystemMode::ClientSideRendering.as_str(), "csr");
    assert_eq!(EcosystemMode::StaticSiteGeneration.as_str(), "ssg");
    assert_eq!(EcosystemMode::HybridRendering.as_str(), "hybrid");

    // Verify Display matches as_str
    assert_eq!(format!("{}", EcosystemMode::ServerSideRendering), "ssr");
    assert_eq!(format!("{}", EcosystemMode::ClientSideRendering), "csr");
}

// ---------------------------------------------------------------------------
// ModuleResolutionStrategy integration tests
// ---------------------------------------------------------------------------

#[test]
fn module_resolution_strategy_all_variants_covered() {
    let all_strategies = ModuleResolutionStrategy::ALL;
    assert_eq!(all_strategies.len(), 4);

    // Verify all expected strategies are present
    assert!(all_strategies.contains(&ModuleResolutionStrategy::NodeExports));
    assert!(all_strategies.contains(&ModuleResolutionStrategy::NodeLegacy));
    assert!(all_strategies.contains(&ModuleResolutionStrategy::WebpackCustom));
    assert!(all_strategies.contains(&ModuleResolutionStrategy::EsmOnly));

    // Verify ordering is deterministic
    let mut sorted = all_strategies.to_vec();
    sorted.sort();
    assert_eq!(&sorted, all_strategies);
}

#[test]
fn module_resolution_strategy_conditions() {
    let node_conditions = ModuleResolutionStrategy::NodeExports.resolution_conditions();
    assert!(node_conditions.contains(&"node"));
    assert!(node_conditions.contains(&"import"));
    assert!(node_conditions.contains(&"require"));

    let legacy_conditions = ModuleResolutionStrategy::NodeLegacy.resolution_conditions();
    assert_eq!(legacy_conditions, &["main"]);

    let webpack_conditions = ModuleResolutionStrategy::WebpackCustom.resolution_conditions();
    assert!(webpack_conditions.contains(&"webpack"));
    assert!(webpack_conditions.contains(&"browser"));
    assert!(webpack_conditions.contains(&"import"));

    let esm_conditions = ModuleResolutionStrategy::EsmOnly.resolution_conditions();
    assert_eq!(esm_conditions, &["import"]);
}

#[test]
fn module_resolution_strategy_string_conversion() {
    assert_eq!(
        ModuleResolutionStrategy::NodeExports.as_str(),
        "node_exports"
    );
    assert_eq!(ModuleResolutionStrategy::NodeLegacy.as_str(), "node_legacy");
    assert_eq!(
        ModuleResolutionStrategy::WebpackCustom.as_str(),
        "webpack_custom"
    );
    assert_eq!(ModuleResolutionStrategy::EsmOnly.as_str(), "esm_only");

    // Verify Display matches as_str
    assert_eq!(
        format!("{}", ModuleResolutionStrategy::NodeExports),
        "node_exports"
    );
    assert_eq!(format!("{}", ModuleResolutionStrategy::EsmOnly), "esm_only");
}

// ---------------------------------------------------------------------------
// EcosystemPattern integration tests
// ---------------------------------------------------------------------------

#[test]
fn ecosystem_pattern_creation_and_builder() {
    let pattern = EcosystemPattern::new(
        "test_pattern".to_string(),
        "Test React pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_package(ReactPackage::ReactDom)
    .with_resolution_strategy(ModuleResolutionStrategy::NodeExports)
    .with_package_config("react".to_string(), "18.0.0".to_string())
    .with_entry_point("index.js".to_string())
    .with_subpath_import("react/jsx-runtime".to_string());

    assert_eq!(pattern.pattern_id, "test_pattern");
    assert_eq!(pattern.description, "Test React pattern");
    assert_eq!(pattern.mode, EcosystemMode::ClientSideRendering);
    assert_eq!(pattern.compile_mode, CompileMode::Automatic);
    assert_eq!(
        pattern.resolution_strategy,
        ModuleResolutionStrategy::NodeExports
    );
    assert_eq!(pattern.required_packages.len(), 2);
    assert!(pattern.required_packages.contains(&ReactPackage::React));
    assert!(pattern.required_packages.contains(&ReactPackage::ReactDom));
    assert_eq!(
        pattern.package_config.get("react"),
        Some(&"18.0.0".to_string())
    );
    assert_eq!(pattern.entry_points, vec!["index.js".to_string()]);
    assert_eq!(
        pattern.subpath_imports,
        vec!["react/jsx-runtime".to_string()]
    );
}

#[test]
fn ecosystem_pattern_validation_success() {
    let valid_pattern = EcosystemPattern::new(
        "valid_csr".to_string(),
        "Valid CSR pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    assert!(valid_pattern.validate().is_ok());
}

#[test]
fn ecosystem_pattern_validation_empty_pattern_id() {
    let invalid_pattern = EcosystemPattern::new(
        "".to_string(),
        "Pattern with empty ID".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let result = invalid_pattern.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        EcosystemCompatibilityError::InvalidPattern { pattern_id, reason } => {
            assert_eq!(pattern_id, "");
            assert!(reason.contains("pattern_id cannot be empty"));
        }
        _ => panic!("Expected InvalidPattern error"),
    }
}

#[test]
fn ecosystem_pattern_validation_no_packages() {
    let invalid_pattern = EcosystemPattern::new(
        "no_packages".to_string(),
        "Pattern without packages".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_entry_point("index.js".to_string());

    let result = invalid_pattern.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        EcosystemCompatibilityError::InvalidPattern { pattern_id, reason } => {
            assert_eq!(pattern_id, "no_packages");
            assert!(reason.contains("at least one required package"));
        }
        _ => panic!("Expected InvalidPattern error"),
    }
}

#[test]
fn ecosystem_pattern_validation_no_entry_points() {
    let invalid_pattern = EcosystemPattern::new(
        "no_entries".to_string(),
        "Pattern without entry points".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React);

    let result = invalid_pattern.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        EcosystemCompatibilityError::InvalidPattern { pattern_id, reason } => {
            assert_eq!(pattern_id, "no_entries");
            assert!(reason.contains("at least one entry point"));
        }
        _ => panic!("Expected InvalidPattern error"),
    }
}

#[test]
fn ecosystem_pattern_validation_ssr_without_server_package() {
    let invalid_ssr_pattern = EcosystemPattern::new(
        "invalid_ssr".to_string(),
        "SSR pattern without server package".to_string(),
        EcosystemMode::ServerSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let result = invalid_ssr_pattern.validate();
    assert!(result.is_err());
    match result.unwrap_err() {
        EcosystemCompatibilityError::InvalidPattern { pattern_id, reason } => {
            assert_eq!(pattern_id, "invalid_ssr");
            assert!(reason.contains("SSR patterns must include ReactDomServer"));
        }
        _ => panic!("Expected InvalidPattern error"),
    }
}

#[test]
fn ecosystem_pattern_validation_ssr_with_server_package() {
    let valid_ssr_pattern = EcosystemPattern::new(
        "valid_ssr".to_string(),
        "Valid SSR pattern".to_string(),
        EcosystemMode::ServerSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_package(ReactPackage::ReactDomServer)
    .with_entry_point("index.js".to_string());

    assert!(valid_ssr_pattern.validate().is_ok());
}

#[test]
fn ecosystem_pattern_hash_deterministic() {
    let pattern1 = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let pattern2 = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    assert_eq!(pattern1.compute_hash(), pattern2.compute_hash());
}

#[test]
fn ecosystem_pattern_hash_different_for_different_patterns() {
    let pattern1 = EcosystemPattern::new(
        "test1".to_string(),
        "Test pattern 1".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let pattern2 = EcosystemPattern::new(
        "test2".to_string(),
        "Test pattern 2".to_string(),
        EcosystemMode::ServerSideRendering,
        CompileMode::Classic,
    )
    .with_package(ReactPackage::ReactDom)
    .with_entry_point("app.js".to_string());

    assert_ne!(pattern1.compute_hash(), pattern2.compute_hash());
}

// ---------------------------------------------------------------------------
// CompatibilityTestResult integration tests
// ---------------------------------------------------------------------------

#[test]
fn compatibility_test_result_creation() {
    let pattern = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let result = CompatibilityTestResult::new(pattern.clone(), true)
        .with_error("Test error".to_string())
        .with_diagnostic("Test diagnostic".to_string())
        .with_execution_time(1500);

    assert!(result.passed);
    assert_eq!(result.pattern, pattern);
    assert_eq!(result.errors, vec!["Test error".to_string()]);
    assert_eq!(result.diagnostics, vec!["Test diagnostic".to_string()]);
    assert_eq!(result.execution_time_ms, 1500);
    assert_eq!(result.input_hash, pattern.compute_hash());
}

#[test]
fn compatibility_test_result_with_metrics() {
    let pattern = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let mut metrics = CompatibilityMetrics::default();
    metrics.packages_resolved = 5;
    metrics.entry_points_loaded = 3;
    metrics.subpaths_resolved = 2;
    metrics.compilations_successful = 1;
    metrics.runtime_operations_successful = 1;

    let result = CompatibilityTestResult::new(pattern, false).with_metrics(metrics.clone());

    assert!(!result.passed);
    assert_eq!(result.metrics, metrics);
}

// ---------------------------------------------------------------------------
// CompatibilityMetrics integration tests
// ---------------------------------------------------------------------------

#[test]
fn compatibility_metrics_default() {
    let metrics = CompatibilityMetrics::default();
    assert_eq!(metrics.packages_resolved, 0);
    assert_eq!(metrics.entry_points_loaded, 0);
    assert_eq!(metrics.subpaths_resolved, 0);
    assert_eq!(metrics.compilations_successful, 0);
    assert_eq!(metrics.runtime_operations_successful, 0);
    assert_eq!(metrics.compatibility_score_millionths, 0);
}

#[test]
fn compatibility_metrics_score_computation() {
    let mut metrics = CompatibilityMetrics::default();
    metrics.packages_resolved = 5;
    metrics.entry_points_loaded = 3;
    metrics.subpaths_resolved = 2;
    metrics.compilations_successful = 1;
    metrics.runtime_operations_successful = 1;

    let score = metrics.compute_compatibility_score();

    // Each category gets 1/5 weight (200,000 millionths each)
    // Expected: 5*200000 + 3*200000 + 2*200000 + 1*200000 + 1*200000 = 2,400,000
    // But that's capped at 1,000,000 millionths
    assert!(score > 0);
    assert!(score <= 1_000_000);
}

#[test]
fn compatibility_metrics_score_zero_operations() {
    let metrics = CompatibilityMetrics::default();
    let score = metrics.compute_compatibility_score();
    assert_eq!(score, 0);
}

// ---------------------------------------------------------------------------
// EcosystemCompatibilityReport integration tests
// ---------------------------------------------------------------------------

#[test]
fn ecosystem_compatibility_report_creation() {
    let epoch = SecurityEpoch::from_raw(12345);
    let report = EcosystemCompatibilityReport::new(epoch);

    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.security_epoch, epoch);
    assert!(report.test_results.is_empty());
    assert_eq!(report.overall_metrics.packages_resolved, 0);
    assert!(!report.gate_passed);
    assert_eq!(
        report.compatibility_threshold_millionths,
        DEFAULT_COMPATIBILITY_THRESHOLD
    );
    assert_eq!(report.total_execution_time_ms, 0);
}

#[test]
fn ecosystem_compatibility_report_add_results() {
    let epoch = SecurityEpoch::from_raw(12345);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    let pattern = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let result = CompatibilityTestResult::new(pattern, true).with_execution_time(1000);

    report.add_test_result(result);
    assert_eq!(report.test_results.len(), 1);
}

#[test]
fn ecosystem_compatibility_report_finalize_success() {
    let epoch = SecurityEpoch::from_raw(12345);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    let pattern = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let result = CompatibilityTestResult::new(pattern, true).with_execution_time(1000);

    report.add_test_result(result);

    let finalize_result = report.finalize();
    assert!(finalize_result.is_ok());
    assert_eq!(report.test_results.len(), 1);
    assert_eq!(report.total_execution_time_ms, 1000);
    assert!(report.gate_passed); // Single passing test should pass gate
}

#[test]
fn ecosystem_compatibility_report_finalize_no_results() {
    let epoch = SecurityEpoch::from_raw(12345);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    let finalize_result = report.finalize();
    assert!(finalize_result.is_err());
    match finalize_result.unwrap_err() {
        EcosystemCompatibilityError::NoTestResults => {}
        _ => panic!("Expected NoTestResults error"),
    }
}

#[test]
fn ecosystem_compatibility_report_pass_percentage() {
    let epoch = SecurityEpoch::from_raw(12345);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    // Add two results: one passing, one failing
    let pattern1 = EcosystemPattern::new(
        "test1".to_string(),
        "Test pattern 1".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let pattern2 = EcosystemPattern::new(
        "test2".to_string(),
        "Test pattern 2".to_string(),
        EcosystemMode::ServerSideRendering,
        CompileMode::Classic,
    )
    .with_package(ReactPackage::ReactDom)
    .with_entry_point("app.js".to_string());

    report.add_test_result(CompatibilityTestResult::new(pattern1, true));
    report.add_test_result(CompatibilityTestResult::new(pattern2, false));

    assert_eq!(report.pass_percentage(), 50.0);
}

#[test]
fn ecosystem_compatibility_report_results_by_mode() {
    let epoch = SecurityEpoch::from_raw(12345);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    let csr_pattern = EcosystemPattern::new(
        "csr".to_string(),
        "CSR pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let ssr_pattern = EcosystemPattern::new(
        "ssr".to_string(),
        "SSR pattern".to_string(),
        EcosystemMode::ServerSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::ReactDomServer)
    .with_entry_point("app.js".to_string());

    report.add_test_result(CompatibilityTestResult::new(csr_pattern, true));
    report.add_test_result(CompatibilityTestResult::new(ssr_pattern, false));

    let by_mode = report.results_by_mode();
    assert_eq!(by_mode.len(), 2);
    assert!(by_mode.contains_key(&EcosystemMode::ClientSideRendering));
    assert!(by_mode.contains_key(&EcosystemMode::ServerSideRendering));
    assert_eq!(by_mode[&EcosystemMode::ClientSideRendering].len(), 1);
    assert_eq!(by_mode[&EcosystemMode::ServerSideRendering].len(), 1);
}

// ---------------------------------------------------------------------------
// EcosystemCompatibilityValidator integration tests
// ---------------------------------------------------------------------------

#[test]
fn ecosystem_compatibility_validator_creation() {
    let epoch = SecurityEpoch::from_raw(12345);
    let validator = EcosystemCompatibilityValidator::new(epoch)
        .with_compatibility_threshold(900_000)
        .with_max_patterns(100);

    assert_eq!(validator.security_epoch, epoch);
    assert_eq!(validator.compatibility_threshold_millionths, 900_000);
    assert_eq!(validator.max_patterns, 100);
}

#[test]
fn ecosystem_compatibility_validator_empty_patterns() {
    let epoch = SecurityEpoch::from_raw(12345);
    let validator = EcosystemCompatibilityValidator::new(epoch);

    let patterns: Vec<EcosystemPattern> = vec![];
    let result = validator.validate_patterns(&patterns);

    assert!(result.is_err());
    match result.unwrap_err() {
        EcosystemCompatibilityError::NoTestResults => {}
        _ => panic!("Expected NoTestResults error"),
    }
}

#[test]
fn ecosystem_compatibility_validator_max_patterns_limit() {
    let epoch = SecurityEpoch::from_raw(12345);
    let validator = EcosystemCompatibilityValidator::new(epoch).with_max_patterns(1);

    let patterns = vec![
        EcosystemPattern::new(
            "pattern1".to_string(),
            "Pattern 1".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_entry_point("index.js".to_string()),
        EcosystemPattern::new(
            "pattern2".to_string(),
            "Pattern 2".to_string(),
            EcosystemMode::ServerSideRendering,
            CompileMode::Classic,
        )
        .with_package(ReactPackage::ReactDomServer)
        .with_entry_point("app.js".to_string()),
    ];

    let result = validator.validate_patterns(&patterns);
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.test_results.len(), 1); // Limited to max_patterns
}

// ---------------------------------------------------------------------------
// Standard ecosystem patterns integration tests
// ---------------------------------------------------------------------------

#[test]
fn standard_ecosystem_patterns_creation() {
    let patterns = create_standard_ecosystem_patterns();
    assert!(!patterns.is_empty());

    // All patterns should be valid
    for pattern in &patterns {
        assert!(
            pattern.validate().is_ok(),
            "Pattern {} should be valid",
            pattern.pattern_id
        );
    }
}

#[test]
fn standard_ecosystem_patterns_coverage() {
    let patterns = create_standard_ecosystem_patterns();

    // Check that we have different ecosystem modes represented
    let modes: std::collections::HashSet<_> = patterns.iter().map(|p| p.mode).collect();
    assert!(modes.contains(&EcosystemMode::ClientSideRendering));
    assert!(modes.contains(&EcosystemMode::ServerSideRendering));
    assert!(modes.contains(&EcosystemMode::HybridRendering));

    // Check that we have different compile modes represented
    let compile_modes: std::collections::HashSet<_> =
        patterns.iter().map(|p| p.compile_mode).collect();
    assert!(compile_modes.contains(&CompileMode::Automatic));
    assert!(compile_modes.contains(&CompileMode::Classic));
}

#[test]
fn standard_ecosystem_patterns_unique_ids() {
    let patterns = create_standard_ecosystem_patterns();

    let mut ids = std::collections::HashSet::new();
    for pattern in &patterns {
        assert!(
            ids.insert(&pattern.pattern_id),
            "Duplicate pattern ID: {}",
            pattern.pattern_id
        );
    }

    assert_eq!(ids.len(), patterns.len());
}

#[test]
fn standard_ecosystem_patterns_ssr_includes_server_packages() {
    let patterns = create_standard_ecosystem_patterns();

    for pattern in &patterns {
        if pattern.mode.requires_server_capabilities() {
            assert!(
                pattern
                    .required_packages
                    .contains(&ReactPackage::ReactDomServer),
                "SSR pattern {} should include ReactDomServer",
                pattern.pattern_id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Error handling integration tests
// ---------------------------------------------------------------------------

#[test]
fn ecosystem_compatibility_error_display() {
    let invalid_pattern_error = EcosystemCompatibilityError::InvalidPattern {
        pattern_id: "test".to_string(),
        reason: "missing packages".to_string(),
    };

    let display = format!("{}", invalid_pattern_error);
    assert!(display.contains("test"));
    assert!(display.contains("missing packages"));

    let no_results_error = EcosystemCompatibilityError::NoTestResults;
    assert_eq!(format!("{}", no_results_error), "No test results available");

    let package_resolution_error = EcosystemCompatibilityError::PackageResolutionFailed {
        package: "react".to_string(),
        error: "not found".to_string(),
    };
    let display = format!("{}", package_resolution_error);
    assert!(display.contains("react"));
    assert!(display.contains("not found"));
}

// ---------------------------------------------------------------------------
// Serde integration tests
// ---------------------------------------------------------------------------

#[test]
fn ecosystem_mode_serde_roundtrip() {
    let mode = EcosystemMode::ServerSideRendering;
    let serialized = serde_json::to_string(&mode).unwrap();
    let deserialized: EcosystemMode = serde_json::from_str(&serialized).unwrap();
    assert_eq!(mode, deserialized);
}

#[test]
fn module_resolution_strategy_serde_roundtrip() {
    let strategy = ModuleResolutionStrategy::WebpackCustom;
    let serialized = serde_json::to_string(&strategy).unwrap();
    let deserialized: ModuleResolutionStrategy = serde_json::from_str(&serialized).unwrap();
    assert_eq!(strategy, deserialized);
}

#[test]
fn ecosystem_pattern_serde_roundtrip() {
    let pattern = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::HybridRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_package(ReactPackage::ReactDom)
    .with_resolution_strategy(ModuleResolutionStrategy::NodeExports)
    .with_package_config("react".to_string(), "18.0.0".to_string())
    .with_entry_point("index.js".to_string())
    .with_subpath_import("react/jsx-runtime".to_string());

    let serialized = serde_json::to_string(&pattern).unwrap();
    let deserialized: EcosystemPattern = serde_json::from_str(&serialized).unwrap();
    assert_eq!(pattern, deserialized);
}

#[test]
fn compatibility_test_result_serde_roundtrip() {
    let pattern = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let result = CompatibilityTestResult::new(pattern, true)
        .with_error("Test error".to_string())
        .with_diagnostic("Test diagnostic".to_string())
        .with_execution_time(1000);

    let serialized = serde_json::to_string(&result).unwrap();
    let deserialized: CompatibilityTestResult = serde_json::from_str(&serialized).unwrap();
    assert_eq!(result.passed, deserialized.passed);
    assert_eq!(result.pattern, deserialized.pattern);
    assert_eq!(result.errors, deserialized.errors);
    assert_eq!(result.diagnostics, deserialized.diagnostics);
    assert_eq!(result.execution_time_ms, deserialized.execution_time_ms);
}

#[test]
fn compatibility_metrics_serde_roundtrip() {
    let mut metrics = CompatibilityMetrics::default();
    metrics.packages_resolved = 5;
    metrics.entry_points_loaded = 3;
    metrics.subpaths_resolved = 2;
    metrics.compilations_successful = 1;
    metrics.runtime_operations_successful = 1;
    metrics.compatibility_score_millionths = 800_000;

    let serialized = serde_json::to_string(&metrics).unwrap();
    let deserialized: CompatibilityMetrics = serde_json::from_str(&serialized).unwrap();
    assert_eq!(metrics, deserialized);
}

#[test]
fn ecosystem_compatibility_report_serde_roundtrip() {
    let epoch = SecurityEpoch::from_raw(12345);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    let pattern = EcosystemPattern::new(
        "test".to_string(),
        "Test pattern".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("index.js".to_string());

    let result = CompatibilityTestResult::new(pattern, true);
    report.add_test_result(result);
    report.finalize().unwrap();

    let serialized = serde_json::to_string(&report).unwrap();
    let deserialized: EcosystemCompatibilityReport = serde_json::from_str(&serialized).unwrap();
    assert_eq!(report.schema_version, deserialized.schema_version);
    assert_eq!(report.security_epoch, deserialized.security_epoch);
    assert_eq!(report.test_results.len(), deserialized.test_results.len());
    assert_eq!(report.gate_passed, deserialized.gate_passed);
}

// ---------------------------------------------------------------------------
// Hash consistency integration tests
// ---------------------------------------------------------------------------

#[test]
fn ecosystem_pattern_hash_consistency_across_runs() {
    let pattern = EcosystemPattern::new(
        "hash_test".to_string(),
        "Hash consistency test".to_string(),
        EcosystemMode::HybridRendering,
        CompileMode::Classic,
    )
    .with_package(ReactPackage::React)
    .with_package(ReactPackage::ReactDom)
    .with_package(ReactPackage::ReactDomServer)
    .with_resolution_strategy(ModuleResolutionStrategy::WebpackCustom)
    .with_package_config("react".to_string(), "17.0.0".to_string())
    .with_package_config("react-dom".to_string(), "17.0.0".to_string())
    .with_entry_point("client.js".to_string())
    .with_entry_point("server.js".to_string())
    .with_subpath_import("react/jsx-runtime".to_string())
    .with_subpath_import("react-dom/server".to_string());

    // Compute hash multiple times and ensure consistency
    let hash1 = pattern.compute_hash();
    let hash2 = pattern.compute_hash();
    let hash3 = pattern.compute_hash();

    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);
}

#[test]
fn ecosystem_compatibility_report_hash_consistency() {
    let epoch = SecurityEpoch::from_raw(67890);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    let pattern = EcosystemPattern::new(
        "hash_test_report".to_string(),
        "Hash test for report".to_string(),
        EcosystemMode::StaticSiteGeneration,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_package(ReactPackage::ReactDomServer)
    .with_entry_point("index.js".to_string());

    let result = CompatibilityTestResult::new(pattern, true).with_execution_time(2000);

    report.add_test_result(result);
    report.finalize().unwrap();

    // Compute hash multiple times and ensure consistency
    let hash1 = report.compute_hash();
    let hash2 = report.compute_hash();
    let hash3 = report.compute_hash();

    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);
    assert_eq!(report.report_hash, hash1);
}

fn failed_report_with_triage() -> EcosystemCompatibilityReport {
    let epoch = SecurityEpoch::from_raw(67891);
    let mut report = EcosystemCompatibilityReport::new(epoch);

    let pattern = EcosystemPattern::new(
        "hash_test_failed_report".to_string(),
        "Hash test for failed report triage coverage".to_string(),
        EcosystemMode::HybridRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_package(ReactPackage::ReactDom)
    .with_package(ReactPackage::ReactDomServer)
    .with_entry_point("react".to_string())
    .with_entry_point("react-dom".to_string())
    .with_entry_point("react-dom/server".to_string())
    .with_entry_point("react-dom/client".to_string())
    .with_subpath_import("react/jsx-runtime".to_string());

    let triage = CompatibilityFailureTriage {
        failure_kind: CompatibilityFailureKind::RuntimeOperation,
        failure: "client hydration runtime missing".to_string(),
        minimized_repro: MinimizedReactEcosystemRepro {
            pattern_id: pattern.pattern_id.clone(),
            mode: pattern.mode,
            compile_mode: pattern.compile_mode,
            resolution_strategy: pattern.resolution_strategy,
            failing_specifier: Some("react-dom/client".to_string()),
            required_packages: pattern.required_packages.clone(),
            entry_points: pattern.entry_points.clone(),
            subpath_imports: pattern.subpath_imports.clone(),
        },
        owner_route: ReactEcosystemOwnerRoute {
            component: COMPONENT.to_string(),
            route: "react-runtime-entrygraph".to_string(),
            bead_id: "bd-1lsy.5.7.2".to_string(),
            owner: "runtime".to_string(),
        },
        shipped_path_classification: ReactShippedPathClassification {
            status: ReactShippedPathStatus::RuntimePrerequisite,
            specifier: Some("react-dom/client".to_string()),
            package: Some(ReactPackage::ReactDom),
            subpath: Some("client".to_string()),
            conditions: vec![ExportCondition::Import, ExportCondition::Default],
            resolved_path: Some("react-dom/client".to_string()),
            reason: "client hydration requires react-dom/client".to_string(),
        },
    };

    let result = CompatibilityTestResult::new(pattern, false)
        .with_error("Runtime operation failed".to_string())
        .with_diagnostic("hydration prereq missing".to_string())
        .with_unresolved_failure(triage)
        .with_execution_time(2000);

    report.add_test_result(result);
    report.finalize().unwrap();
    report
}

#[test]
fn ecosystem_compatibility_report_hash_changes_with_unresolved_triage_payloads() {
    let baseline = failed_report_with_triage();

    let mut changed_failure_kind = baseline.clone();
    changed_failure_kind.test_results[0].unresolved_failures[0].failure_kind =
        CompatibilityFailureKind::Compilation;
    changed_failure_kind.finalize().unwrap();
    assert_ne!(baseline.report_hash, changed_failure_kind.report_hash);

    let mut changed_specifier = baseline.clone();
    changed_specifier.test_results[0].unresolved_failures[0]
        .minimized_repro
        .failing_specifier = Some("react/jsx-runtime".to_string());
    changed_specifier.finalize().unwrap();
    assert_ne!(baseline.report_hash, changed_specifier.report_hash);

    let mut changed_owner_route = baseline.clone();
    changed_owner_route.test_results[0].unresolved_failures[0]
        .owner_route
        .route = "react-compile-verification".to_string();
    changed_owner_route.finalize().unwrap();
    assert_ne!(baseline.report_hash, changed_owner_route.report_hash);

    let mut changed_classification_status = baseline.clone();
    changed_classification_status.test_results[0].unresolved_failures[0]
        .shipped_path_classification
        .status = ReactShippedPathStatus::UnrecognizedSpecifier;
    changed_classification_status.finalize().unwrap();
    assert_ne!(
        baseline.report_hash,
        changed_classification_status.report_hash
    );

    let mut changed_classification_reason = baseline.clone();
    changed_classification_reason.test_results[0].unresolved_failures[0]
        .shipped_path_classification
        .reason = "specifier is outside the shipped React cohort".to_string();
    changed_classification_reason.finalize().unwrap();
    assert_ne!(
        baseline.report_hash,
        changed_classification_reason.report_hash
    );

    let mut changed_error = baseline.clone();
    changed_error.test_results[0]
        .errors
        .push("secondary runtime detail".to_string());
    changed_error.finalize().unwrap();
    assert_ne!(baseline.report_hash, changed_error.report_hash);
}

// ---------------------------------------------------------------------------
// Cohort-backed validator regressions
// ---------------------------------------------------------------------------

#[test]
fn validator_accepts_standard_patterns_against_checked_in_react_cohort() {
    let epoch = SecurityEpoch::from_raw(405);
    let validator = EcosystemCompatibilityValidator::new(epoch);
    let patterns = create_standard_ecosystem_patterns();

    let report = validator.validate_patterns(&patterns).unwrap();

    assert!(report.gate_passed);
    assert_eq!(report.test_results.len(), patterns.len());
    assert!(
        report
            .test_results
            .iter()
            .all(|result| result.passed && result.errors.is_empty())
    );
    assert!(report.overall_metrics.packages_resolved >= patterns.len());
    assert!(report.overall_metrics.entry_points_loaded >= patterns.len());
    assert!(report.overall_metrics.subpaths_resolved >= 3);
}

#[test]
fn validator_fails_closed_on_unknown_react_entrypoint() {
    let epoch = SecurityEpoch::from_raw(405);
    let validator = EcosystemCompatibilityValidator::new(epoch);
    let pattern = EcosystemPattern::new(
        "unknown_entrypoint".to_string(),
        "Unknown React entry point must not be treated as compatible".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Classic,
    )
    .with_package(ReactPackage::React)
    .with_entry_point("react/not-a-real-entry".to_string());

    let report = validator.validate_patterns(&[pattern]).unwrap();

    assert!(!report.gate_passed);
    assert_eq!(report.test_results.len(), 1);
    let result = &report.test_results[0];
    assert!(!result.passed);
    assert!(
        result
            .errors
            .iter()
            .any(|error| error.contains("Entry point loading failed"))
    );
    let triage = result
        .unresolved_failures
        .iter()
        .find(|failure| {
            failure.failure_kind == CompatibilityFailureKind::EntryPointLoading
                && failure.minimized_repro.failing_specifier.as_deref()
                    == Some("react/not-a-real-entry")
        })
        .expect("unknown entry point should produce routed entrygraph triage");
    assert_eq!(triage.owner_route.route, "react-entrygraph-resolution");
    assert_eq!(
        triage.shipped_path_classification.status,
        ReactShippedPathStatus::UnrecognizedSpecifier
    );
}

#[test]
fn automatic_compile_requires_declared_jsx_runtime_import() {
    let epoch = SecurityEpoch::from_raw(405);
    let validator = EcosystemCompatibilityValidator::new(epoch);
    let pattern = EcosystemPattern::new(
        "automatic_without_runtime_import".to_string(),
        "Automatic JSX mode must declare the runtime import it depends on".to_string(),
        EcosystemMode::ClientSideRendering,
        CompileMode::Automatic,
    )
    .with_package(ReactPackage::React)
    .with_package(ReactPackage::ReactDom)
    .with_package(ReactPackage::ReactJsxRuntime)
    .with_entry_point("react".to_string())
    .with_entry_point("react-dom".to_string());

    let report = validator.validate_patterns(&[pattern]).unwrap();

    assert!(!report.gate_passed);
    let result = &report.test_results[0];
    assert!(!result.passed);
    assert!(
        result
            .errors
            .iter()
            .any(|error| error == "Compilation test failed")
    );
    let triage = result
        .unresolved_failures
        .iter()
        .find(|failure| {
            failure.failure_kind == CompatibilityFailureKind::Compilation
                && failure.minimized_repro.failing_specifier.as_deref() == Some("react/jsx-runtime")
        })
        .expect("automatic JSX mode should produce compilation triage for react/jsx-runtime");
    assert_eq!(triage.failure_kind, CompatibilityFailureKind::Compilation);
    assert_eq!(
        triage.minimized_repro.failing_specifier.as_deref(),
        Some("react/jsx-runtime")
    );
    assert_eq!(triage.owner_route.route, "react-compile-verification");
    assert_eq!(
        triage.shipped_path_classification.status,
        ReactShippedPathStatus::Shipped
    );
}
