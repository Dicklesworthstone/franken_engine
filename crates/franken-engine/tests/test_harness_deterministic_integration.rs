//! Integration tests for deterministic test harness utilities
//!
//! These tests validate the cross-lane integration behavior of the test harness
//! utilities and ensure deterministic execution across runtime, parser, and
//! security test scenarios.

#![forbid(unsafe_code)]

use frankenengine_engine::test_harness_deterministic::*;
use std::path::PathBuf;

#[test]
fn test_cross_platform_deterministic_execution() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 424242,
        timeout_millis: 60000,
        artifact_dir: PathBuf::from("target/test_harness_integration"),
        isolation: TestIsolationLevel::Complete,
    };

    let mut runner = TestSuiteRunner::new(config);

    let suite = TestSuite {
        suite_id: "cross_platform_integration".to_string(),
        runtime_tests: vec![
            RuntimeTestSpec {
                test_id: "runtime_cross_platform_1".to_string(),
                source_complexity: SourceComplexity::Complex,
                data_size: 10,
                expected_outcome: TestOutcome::Success,
            },
            RuntimeTestSpec {
                test_id: "runtime_cross_platform_2".to_string(),
                source_complexity: SourceComplexity::Moderate,
                data_size: 5,
                expected_outcome: TestOutcome::Success,
            },
        ],
        parser_tests: vec![ParserTestSpec {
            test_id: "parser_cross_platform_1".to_string(),
            source_complexity: SourceComplexity::Complex,
            syntax_features: vec![
                SyntaxFeature::ArrowFunctions,
                SyntaxFeature::AsyncAwait,
                SyntaxFeature::Classes,
            ],
            expected_outcome: TestOutcome::Success,
        }],
        security_tests: vec![SecurityTestSpec {
            test_id: "security_cross_platform_1".to_string(),
            threat_vectors: vec![
                ThreatVector::CodeInjection,
                ThreatVector::PrototypePollution,
                ThreatVector::PathTraversal,
            ],
            security_level: SecurityLevel::High,
            expected_outcome: TestOutcome::Success,
        }],
    };

    let result = runner.execute_test_suite(suite);

    assert_eq!(result.suite_id, "cross_platform_integration");
    assert_eq!(result.total_tests, 4);
    assert!(result.passed_tests > 0);
    assert_eq!(result.results.len(), 4);
    assert_eq!(result.deterministic_seed, 424242);
}

#[test]
fn test_deterministic_reproducibility_across_runs() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 777888,
        timeout_millis: 30000,
        artifact_dir: PathBuf::from("target/test_harness_reproducibility"),
        isolation: TestIsolationLevel::Process,
    };

    let suite = TestSuite {
        suite_id: "reproducibility_test".to_string(),
        runtime_tests: vec![RuntimeTestSpec {
            test_id: "reproducibility_runtime".to_string(),
            source_complexity: SourceComplexity::Moderate,
            data_size: 7,
            expected_outcome: TestOutcome::Success,
        }],
        parser_tests: vec![ParserTestSpec {
            test_id: "reproducibility_parser".to_string(),
            source_complexity: SourceComplexity::Simple,
            syntax_features: vec![SyntaxFeature::Modules, SyntaxFeature::TemplateStrings],
            expected_outcome: TestOutcome::Success,
        }],
        security_tests: vec![SecurityTestSpec {
            test_id: "reproducibility_security".to_string(),
            threat_vectors: vec![ThreatVector::DenialOfService],
            security_level: SecurityLevel::Medium,
            expected_outcome: TestOutcome::Success,
        }],
    };

    // Execute the same suite multiple times
    let mut runner1 = TestSuiteRunner::new(config.clone());
    let mut runner2 = TestSuiteRunner::new(config.clone());
    let mut runner3 = TestSuiteRunner::new(config);

    let result1 = runner1.execute_test_suite(suite.clone());
    let result2 = runner2.execute_test_suite(suite.clone());
    let result3 = runner3.execute_test_suite(suite);

    // Verify deterministic results across runs
    assert_eq!(result1.total_tests, result2.total_tests);
    assert_eq!(result2.total_tests, result3.total_tests);

    assert_eq!(result1.passed_tests, result2.passed_tests);
    assert_eq!(result2.passed_tests, result3.passed_tests);

    // Individual test results should be identical
    for i in 0..result1.results.len() {
        assert_eq!(result1.results[i].success, result2.results[i].success);
        assert_eq!(result2.results[i].success, result3.results[i].success);
        assert_eq!(result1.results[i].test_id, result2.results[i].test_id);
        assert_eq!(
            result1.results[i].artifacts.len(),
            result2.results[i].artifacts.len()
        );
    }
}

#[test]
fn test_runtime_parser_security_lane_integration() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 555666,
        timeout_millis: 45000,
        artifact_dir: PathBuf::from("target/test_harness_lane_integration"),
        isolation: TestIsolationLevel::Shared,
    };

    let mut runtime_harness = RuntimeTestHarness::new(config.clone());
    let mut parser_harness = ParserTestHarness::new(config.clone());
    let mut security_harness = SecurityTestHarness::new(config);

    // Test runtime lane
    let runtime_spec = RuntimeTestSpec {
        test_id: "lane_integration_runtime".to_string(),
        source_complexity: SourceComplexity::Complex,
        data_size: 15,
        expected_outcome: TestOutcome::Success,
    };
    let runtime_result = runtime_harness.execute_runtime_test(runtime_spec);

    // Test parser lane
    let parser_spec = ParserTestSpec {
        test_id: "lane_integration_parser".to_string(),
        source_complexity: SourceComplexity::Complex,
        syntax_features: vec![
            SyntaxFeature::ArrowFunctions,
            SyntaxFeature::Destructuring,
            SyntaxFeature::AsyncAwait,
            SyntaxFeature::Classes,
            SyntaxFeature::Modules,
        ],
        expected_outcome: TestOutcome::Success,
    };
    let parser_result = parser_harness.execute_parser_test(parser_spec);

    // Test security lane
    let security_spec = SecurityTestSpec {
        test_id: "lane_integration_security".to_string(),
        threat_vectors: vec![
            ThreatVector::CodeInjection,
            ThreatVector::PrototypePollution,
            ThreatVector::PathTraversal,
            ThreatVector::DenialOfService,
            ThreatVector::PrivilegeEscalation,
        ],
        security_level: SecurityLevel::Critical,
        expected_outcome: TestOutcome::Success,
    };
    let security_result = security_harness.execute_security_test(security_spec);

    // Verify all lanes executed successfully
    assert_eq!(runtime_result.test_id, "lane_integration_runtime");
    assert_eq!(parser_result.test_id, "lane_integration_parser");
    assert_eq!(security_result.test_id, "lane_integration_security");

    // Verify deterministic seed consistency across lanes
    assert_eq!(runtime_result.deterministic_seed, 555666);
    assert_eq!(parser_result.deterministic_seed, 555666);
    assert_eq!(security_result.deterministic_seed, 555666);

    // Verify artifacts generation
    assert!(!runtime_result.artifacts.is_empty());
    assert!(!parser_result.artifacts.is_empty());
    assert!(!security_result.artifacts.is_empty());
}

#[test]
fn test_test_fixture_generator_integration() {
    let mut generator = TestFixtureGenerator::new(123789);

    // Test different complexity levels
    let simple_source = generator.generate_source(SourceComplexity::Simple);
    let moderate_source = generator.generate_source(SourceComplexity::Moderate);
    let complex_source = generator.generate_source(SourceComplexity::Complex);

    // Verify distinct generated content
    assert_ne!(simple_source.content, moderate_source.content);
    assert_ne!(moderate_source.content, complex_source.content);
    assert_ne!(simple_source.id, moderate_source.id);

    // Test data generation with different sizes
    let small_data = generator.generate_test_data(3);
    let large_data = generator.generate_test_data(20);

    assert_eq!(small_data.entries.len(), 3);
    assert_eq!(large_data.entries.len(), 20);
    assert_ne!(small_data.id, large_data.id);
    assert_eq!(small_data.generation_seed, large_data.generation_seed);
}

#[test]
fn test_comprehensive_syntax_feature_coverage() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Parser,
        deterministic_seed: 987654,
        timeout_millis: 60000,
        artifact_dir: PathBuf::from("target/test_harness_syntax"),
        isolation: TestIsolationLevel::Complete,
    };

    let mut harness = ParserTestHarness::new(config);

    let all_features = vec![
        SyntaxFeature::ArrowFunctions,
        SyntaxFeature::AsyncAwait,
        SyntaxFeature::Classes,
        SyntaxFeature::Destructuring,
        SyntaxFeature::Modules,
        SyntaxFeature::TemplateStrings,
    ];

    let spec = ParserTestSpec {
        test_id: "comprehensive_syntax_test".to_string(),
        source_complexity: SourceComplexity::Complex,
        syntax_features: all_features,
        expected_outcome: TestOutcome::Success,
    };

    let result = harness.execute_parser_test(spec);

    assert_eq!(result.test_id, "comprehensive_syntax_test");
    assert_eq!(result.deterministic_seed, 987654);
    assert!(result.execution_time_millis > 0);
    assert_eq!(result.artifacts.len(), 2);
}

#[test]
fn test_comprehensive_threat_vector_coverage() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Security,
        deterministic_seed: 456789,
        timeout_millis: 90000,
        artifact_dir: PathBuf::from("target/test_harness_security"),
        isolation: TestIsolationLevel::Process,
    };

    let mut harness = SecurityTestHarness::new(config);

    let all_threats = vec![
        ThreatVector::CodeInjection,
        ThreatVector::PrototypePollution,
        ThreatVector::PathTraversal,
        ThreatVector::DenialOfService,
        ThreatVector::PrivilegeEscalation,
    ];

    let spec = SecurityTestSpec {
        test_id: "comprehensive_threat_test".to_string(),
        threat_vectors: all_threats,
        security_level: SecurityLevel::Critical,
        expected_outcome: TestOutcome::Success,
    };

    let result = harness.execute_security_test(spec);

    assert_eq!(result.test_id, "comprehensive_threat_test");
    assert_eq!(result.deterministic_seed, 456789);
    assert!(result.execution_time_millis > 0);
    assert_eq!(result.artifacts.len(), 2);
}

#[test]
fn test_isolation_level_behavior() {
    let base_config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 111222,
        timeout_millis: 30000,
        artifact_dir: PathBuf::from("target/test_harness_isolation"),
        isolation: TestIsolationLevel::Complete,
    };

    // Test different isolation levels
    let complete_config = TestHarnessConfig {
        isolation: TestIsolationLevel::Complete,
        ..base_config.clone()
    };

    let shared_config = TestHarnessConfig {
        isolation: TestIsolationLevel::Shared,
        ..base_config.clone()
    };

    let process_config = TestHarnessConfig {
        isolation: TestIsolationLevel::Process,
        ..base_config
    };

    let runner_complete = TestSuiteRunner::new(complete_config);
    let runner_shared = TestSuiteRunner::new(shared_config);
    let runner_process = TestSuiteRunner::new(process_config);

    // Verify different isolation levels can be instantiated
    assert!(matches!(
        runner_complete.config.isolation,
        TestIsolationLevel::Complete
    ));
    assert!(matches!(
        runner_shared.config.isolation,
        TestIsolationLevel::Shared
    ));
    assert!(matches!(
        runner_process.config.isolation,
        TestIsolationLevel::Process
    ));
}

#[test]
fn test_execution_mode_behavior() {
    let base_config = TestHarnessConfig {
        mode: TestExecutionMode::Unit,
        deterministic_seed: 333444,
        timeout_millis: 30000,
        artifact_dir: PathBuf::from("target/test_harness_modes"),
        isolation: TestIsolationLevel::Complete,
    };

    // Test different execution modes
    let modes = vec![
        TestExecutionMode::Unit,
        TestExecutionMode::Integration,
        TestExecutionMode::E2E,
        TestExecutionMode::Security,
        TestExecutionMode::Parser,
    ];

    for mode in modes {
        let config = TestHarnessConfig {
            mode: mode.clone(),
            ..base_config.clone()
        };

        let runner = TestSuiteRunner::new(config);

        // Verify mode is set correctly
        match mode {
            TestExecutionMode::Unit => {
                assert!(matches!(runner.config.mode, TestExecutionMode::Unit))
            }
            TestExecutionMode::Integration => {
                assert!(matches!(runner.config.mode, TestExecutionMode::Integration))
            }
            TestExecutionMode::E2E => assert!(matches!(runner.config.mode, TestExecutionMode::E2E)),
            TestExecutionMode::Security => {
                assert!(matches!(runner.config.mode, TestExecutionMode::Security))
            }
            TestExecutionMode::Parser => {
                assert!(matches!(runner.config.mode, TestExecutionMode::Parser))
            }
        }
    }
}

#[test]
fn test_timeout_behavior() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 555777,
        timeout_millis: 1000, // Short timeout for testing
        artifact_dir: PathBuf::from("target/test_harness_timeout"),
        isolation: TestIsolationLevel::Complete,
    };

    let mut runner = TestSuiteRunner::new(config);

    let suite = TestSuite {
        suite_id: "timeout_test".to_string(),
        runtime_tests: vec![RuntimeTestSpec {
            test_id: "timeout_runtime_test".to_string(),
            source_complexity: SourceComplexity::Simple,
            data_size: 1,
            expected_outcome: TestOutcome::Success,
        }],
        parser_tests: vec![],
        security_tests: vec![],
    };

    let result = runner.execute_test_suite(suite);

    // Test should complete within reasonable time despite short configured timeout
    assert_eq!(result.suite_id, "timeout_test");
    assert_eq!(result.total_tests, 1);
    assert!(result.execution_time_millis < 5000); // Should be much faster than 5 seconds
}

#[test]
fn test_artifact_directory_usage() {
    let custom_dir = PathBuf::from("target/custom_test_artifacts");

    let config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 888999,
        timeout_millis: 30000,
        artifact_dir: custom_dir.clone(),
        isolation: TestIsolationLevel::Complete,
    };

    let runner = TestSuiteRunner::new(config);

    // Verify custom artifact directory is set
    assert_eq!(runner.config.artifact_dir, custom_dir);
}

#[test]
fn test_large_scale_test_suite() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 121314,
        timeout_millis: 120000, // Longer timeout for large suite
        artifact_dir: PathBuf::from("target/test_harness_large"),
        isolation: TestIsolationLevel::Shared,
    };

    let mut runner = TestSuiteRunner::new(config);

    // Create a large test suite
    let mut runtime_tests = Vec::new();
    let mut parser_tests = Vec::new();
    let mut security_tests = Vec::new();

    for i in 0..10 {
        runtime_tests.push(RuntimeTestSpec {
            test_id: format!("large_runtime_{}", i),
            source_complexity: if i % 3 == 0 {
                SourceComplexity::Complex
            } else if i % 2 == 0 {
                SourceComplexity::Moderate
            } else {
                SourceComplexity::Simple
            },
            data_size: i + 1,
            expected_outcome: TestOutcome::Success,
        });
    }

    for i in 0..5 {
        parser_tests.push(ParserTestSpec {
            test_id: format!("large_parser_{}", i),
            source_complexity: SourceComplexity::Complex,
            syntax_features: vec![
                SyntaxFeature::ArrowFunctions,
                SyntaxFeature::Classes,
                SyntaxFeature::Modules,
            ],
            expected_outcome: TestOutcome::Success,
        });
    }

    for i in 0..3 {
        security_tests.push(SecurityTestSpec {
            test_id: format!("large_security_{}", i),
            threat_vectors: vec![ThreatVector::CodeInjection, ThreatVector::DenialOfService],
            security_level: SecurityLevel::High,
            expected_outcome: TestOutcome::Success,
        });
    }

    let suite = TestSuite {
        suite_id: "large_scale_test_suite".to_string(),
        runtime_tests,
        parser_tests,
        security_tests,
    };

    let result = runner.execute_test_suite(suite);

    assert_eq!(result.suite_id, "large_scale_test_suite");
    assert_eq!(result.total_tests, 18); // 10 + 5 + 3
    assert_eq!(result.results.len(), 18);
    assert!(result.passed_tests > 0);
    assert_eq!(result.deterministic_seed, 121314);
}

#[test]
fn test_default_configuration() {
    let config = TestHarnessConfig::default();

    assert!(matches!(config.mode, TestExecutionMode::Unit));
    assert_eq!(config.deterministic_seed, 12345);
    assert_eq!(config.timeout_millis, 30000);
    assert_eq!(config.artifact_dir, PathBuf::from("target/test_artifacts"));
    assert!(matches!(config.isolation, TestIsolationLevel::Complete));
}

#[test]
fn test_serialization_compatibility() {
    let config = TestHarnessConfig {
        mode: TestExecutionMode::Integration,
        deterministic_seed: 999888,
        timeout_millis: 45000,
        artifact_dir: PathBuf::from("target/serialization_test"),
        isolation: TestIsolationLevel::Process,
    };

    // Test that all types can be serialized/deserialized
    let json = serde_json::to_string(&config).expect("Should serialize config");
    assert!(!json.is_empty());

    let deserialized: TestHarnessConfig =
        serde_json::from_str(&json).expect("Should deserialize config");

    assert_eq!(deserialized.deterministic_seed, 999888);
    assert_eq!(deserialized.timeout_millis, 45000);
    assert!(matches!(deserialized.mode, TestExecutionMode::Integration));
    assert!(matches!(
        deserialized.isolation,
        TestIsolationLevel::Process
    ));
}
