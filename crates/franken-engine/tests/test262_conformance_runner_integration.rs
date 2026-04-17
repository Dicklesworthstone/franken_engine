use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::test262_conformance_runner::{
    BEAD_ID, COMPONENT, ConformanceReport, DEFAULT_TEST262_URL, MILLIONTHS, RunnerConfig,
    SCHEMA_VERSION, Test262Runner, TestCategory, TestRecord, TestResult, TestStatistics,
};
use std::path::PathBuf;

#[test]
fn test_schema_version_format() {
    assert!(SCHEMA_VERSION.contains("test262-conformance-runner"));
    assert!(SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "test262_conformance_runner");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-axlvk.3");
}

#[test]
fn test_default_test262_url() {
    assert!(DEFAULT_TEST262_URL.contains("tc39/test262"));
    assert!(DEFAULT_TEST262_URL.contains("github.com"));
}

#[test]
fn test_millionths_constant() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn test_result_variants_complete() {
    let results = [
        TestResult::Pass,
        TestResult::Fail,
        TestResult::Skip,
        TestResult::Error,
    ];
    for result in results {
        assert!(!result.as_str().is_empty());
    }
}

#[test]
fn test_result_display_matches_as_str() {
    let results = [
        TestResult::Pass,
        TestResult::Fail,
        TestResult::Skip,
        TestResult::Error,
    ];
    for result in results {
        assert_eq!(format!("{}", result), result.as_str());
    }
}

#[test]
fn test_result_is_passing_logic() {
    assert!(TestResult::Pass.is_passing());
    assert!(!TestResult::Fail.is_passing());
    assert!(!TestResult::Skip.is_passing());
    assert!(!TestResult::Error.is_passing());
}

#[test]
fn test_result_ordering() {
    let mut results = [
        TestResult::Error,
        TestResult::Pass,
        TestResult::Skip,
        TestResult::Fail,
    ];
    results.sort();
    assert_eq!(
        results,
        [
            TestResult::Pass,
            TestResult::Fail,
            TestResult::Skip,
            TestResult::Error
        ]
    );
}

#[test]
fn test_category_as_str_all() {
    assert_eq!(TestCategory::Language.as_str(), "language");
    assert_eq!(TestCategory::BuiltIns.as_str(), "built-ins");
    assert_eq!(TestCategory::Intl.as_str(), "intl");
    assert_eq!(TestCategory::Annexes.as_str(), "annexes");
    assert_eq!(TestCategory::Harness.as_str(), "harness");
}

#[test]
fn test_category_display_matches_as_str() {
    let categories = [
        TestCategory::Language,
        TestCategory::BuiltIns,
        TestCategory::Intl,
        TestCategory::Annexes,
        TestCategory::Harness,
    ];
    for category in categories {
        assert_eq!(format!("{}", category), category.as_str());
    }
}

#[test]
fn test_category_from_path_language() {
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/language/expressions/array.js")),
        TestCategory::Language
    );
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/LANGUAGE/stmt.js")),
        TestCategory::Language
    );
}

#[test]
fn test_category_from_path_builtins() {
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/built-ins/Array/prototype.js")),
        TestCategory::BuiltIns
    );
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/builtins/Object.js")),
        TestCategory::BuiltIns
    );
}

#[test]
fn test_category_from_path_intl() {
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/intl/Collator.js")),
        TestCategory::Intl
    );
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/INTL/Locale.js")),
        TestCategory::Intl
    );
}

#[test]
fn test_category_from_path_annexes() {
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/annexes/b/regexp.js")),
        TestCategory::Annexes
    );
}

#[test]
fn test_category_from_path_harness() {
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/harness/assert.js")),
        TestCategory::Harness
    );
}

#[test]
fn test_category_from_path_default() {
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("test/unknown/path.js")),
        TestCategory::Language
    );
    assert_eq!(
        TestCategory::from_path(&PathBuf::from("some/other/path.js")),
        TestCategory::Language
    );
}

#[test]
fn test_test_record_new() {
    let path = PathBuf::from("test/language/example.js");
    let record = TestRecord::new(path.clone(), TestResult::Pass, 1000, None, false);

    assert_eq!(record.path, path);
    assert_eq!(record.category, TestCategory::Language);
    assert_eq!(record.result, TestResult::Pass);
    assert_eq!(record.duration_us, 1000);
    assert_eq!(record.error_message, None);
    assert!(!record.is_negative);
}

#[test]
fn test_test_record_with_error() {
    let record = TestRecord::new(
        PathBuf::from("test/built-ins/error.js"),
        TestResult::Error,
        500,
        Some("Parse error".to_string()),
        true,
    );

    assert_eq!(record.category, TestCategory::BuiltIns);
    assert_eq!(record.result, TestResult::Error);
    assert_eq!(record.error_message, Some("Parse error".to_string()));
    assert!(record.is_negative);
}

#[test]
fn test_statistics_empty_records() {
    let stats = TestStatistics::from_records(&[]);
    assert_eq!(stats.total_tests, 0);
    assert_eq!(stats.passed, 0);
    assert_eq!(stats.failed, 0);
    assert_eq!(stats.skipped, 0);
    assert_eq!(stats.errored, 0);
    assert_eq!(stats.pass_rate_millionths, 0);
    assert_eq!(stats.total_duration_us, 0);
    assert_eq!(stats.pass_rate_percent(), 0.0);
}

#[test]
fn test_statistics_all_passing() {
    let records = vec![
        TestRecord::new(PathBuf::from("a.js"), TestResult::Pass, 100, None, false),
        TestRecord::new(PathBuf::from("b.js"), TestResult::Pass, 200, None, false),
        TestRecord::new(PathBuf::from("c.js"), TestResult::Pass, 300, None, false),
    ];

    let stats = TestStatistics::from_records(&records);
    assert_eq!(stats.total_tests, 3);
    assert_eq!(stats.passed, 3);
    assert_eq!(stats.failed, 0);
    assert_eq!(stats.skipped, 0);
    assert_eq!(stats.errored, 0);
    assert_eq!(stats.pass_rate_millionths, MILLIONTHS); // 100%
    assert_eq!(stats.total_duration_us, 600);
    assert!((stats.pass_rate_percent() - 100.0).abs() < 0.01);
}

#[test]
fn test_statistics_mixed_results() {
    let records = vec![
        TestRecord::new(PathBuf::from("pass.js"), TestResult::Pass, 100, None, false),
        TestRecord::new(
            PathBuf::from("fail.js"),
            TestResult::Fail,
            200,
            Some("fail".to_string()),
            false,
        ),
        TestRecord::new(PathBuf::from("skip.js"), TestResult::Skip, 50, None, false),
        TestRecord::new(
            PathBuf::from("error.js"),
            TestResult::Error,
            150,
            Some("error".to_string()),
            false,
        ),
    ];

    let stats = TestStatistics::from_records(&records);
    assert_eq!(stats.total_tests, 4);
    assert_eq!(stats.passed, 1);
    assert_eq!(stats.failed, 1);
    assert_eq!(stats.skipped, 1);
    assert_eq!(stats.errored, 1);
    assert_eq!(stats.pass_rate_millionths, 250_000); // 25%
    assert_eq!(stats.total_duration_us, 500);
    assert!((stats.pass_rate_percent() - 25.0).abs() < 0.01);
}

#[test]
fn test_runner_config_default() {
    let config = RunnerConfig::default();
    assert_eq!(config.test262_path, PathBuf::from("test262"));
    assert_eq!(config.max_tests, 1000);
    assert_eq!(config.pattern, None);
    assert!(config.include_negative);
    assert_eq!(config.timeout_ms, 5000);
}

#[test]
fn test_runner_config_custom() {
    let config = RunnerConfig {
        test262_path: PathBuf::from("/custom/test262"),
        max_tests: 500,
        pattern: Some("**/*.js".to_string()),
        include_negative: false,
        timeout_ms: 10000,
    };

    assert_eq!(config.test262_path, PathBuf::from("/custom/test262"));
    assert_eq!(config.max_tests, 500);
    assert_eq!(config.pattern, Some("**/*.js".to_string()));
    assert!(!config.include_negative);
    assert_eq!(config.timeout_ms, 10000);
}

#[test]
fn test_runner_creation() {
    let config = RunnerConfig::default();
    let runner = Test262Runner::new(config);
    assert_eq!(runner.config.max_tests, 1000);
}

#[test]
fn test_conformance_report_new() {
    let epoch = SecurityEpoch::from_raw(42);
    let records = vec![
        TestRecord::new(
            PathBuf::from("test/language/a.js"),
            TestResult::Pass,
            100,
            None,
            false,
        ),
        TestRecord::new(
            PathBuf::from("test/built-ins/b.js"),
            TestResult::Fail,
            200,
            Some("error".to_string()),
            false,
        ),
    ];

    let report = ConformanceReport::new(
        epoch,
        "test-commit-hash".to_string(),
        records.clone(),
        5000,
        true,
    );

    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.security_epoch, epoch);
    assert_eq!(report.test262_commit, "test-commit-hash");
    assert_eq!(report.overall.total_tests, 2);
    assert_eq!(report.overall.passed, 1);
    assert_eq!(report.overall.failed, 1);
    assert_eq!(report.test_records.len(), 2);
    assert_eq!(report.total_discovered, 5000);
    assert!(report.is_sample);
    assert!(!report.timestamp.is_empty());
}

#[test]
fn test_conformance_report_categories() {
    let epoch = SecurityEpoch::from_raw(1);
    let records = vec![
        TestRecord::new(
            PathBuf::from("test/language/a.js"),
            TestResult::Pass,
            100,
            None,
            false,
        ),
        TestRecord::new(
            PathBuf::from("test/language/b.js"),
            TestResult::Fail,
            100,
            Some("fail".to_string()),
            false,
        ),
        TestRecord::new(
            PathBuf::from("test/built-ins/c.js"),
            TestResult::Pass,
            100,
            None,
            false,
        ),
        TestRecord::new(
            PathBuf::from("test/intl/d.js"),
            TestResult::Skip,
            100,
            None,
            false,
        ),
        TestRecord::new(
            PathBuf::from("test/annexes/e.js"),
            TestResult::Error,
            100,
            Some("error".to_string()),
            false,
        ),
        TestRecord::new(
            PathBuf::from("test/harness/f.js"),
            TestResult::Pass,
            100,
            None,
            false,
        ),
    ];

    let report = ConformanceReport::new(epoch, "commit".to_string(), records, 1000, false);

    // Check that all categories are present
    assert!(report.by_category.contains_key(&TestCategory::Language));
    assert!(report.by_category.contains_key(&TestCategory::BuiltIns));
    assert!(report.by_category.contains_key(&TestCategory::Intl));
    assert!(report.by_category.contains_key(&TestCategory::Annexes));
    assert!(report.by_category.contains_key(&TestCategory::Harness));

    // Check language category stats
    let language_stats = &report.by_category[&TestCategory::Language];
    assert_eq!(language_stats.total_tests, 2);
    assert_eq!(language_stats.passed, 1);
    assert_eq!(language_stats.failed, 1);

    // Check built-ins category stats
    let builtins_stats = &report.by_category[&TestCategory::BuiltIns];
    assert_eq!(builtins_stats.total_tests, 1);
    assert_eq!(builtins_stats.passed, 1);

    // Check intl category stats
    let intl_stats = &report.by_category[&TestCategory::Intl];
    assert_eq!(intl_stats.total_tests, 1);
    assert_eq!(intl_stats.skipped, 1);

    // Check annexes category stats
    let annexes_stats = &report.by_category[&TestCategory::Annexes];
    assert_eq!(annexes_stats.total_tests, 1);
    assert_eq!(annexes_stats.errored, 1);

    // Check harness category stats
    let harness_stats = &report.by_category[&TestCategory::Harness];
    assert_eq!(harness_stats.total_tests, 1);
    assert_eq!(harness_stats.passed, 1);
}

#[test]
fn test_runner_mock_execution() {
    let config = RunnerConfig {
        max_tests: 10,
        ..RunnerConfig::default()
    };
    let runner = Test262Runner::new(config);
    let epoch = SecurityEpoch::from_raw(1);

    let result = runner.run_conformance(epoch);
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.security_epoch, epoch);
    assert_eq!(report.overall.total_tests, 10);
    assert!(report.total_discovered >= report.overall.total_tests);
    assert!(report.is_sample);
    assert!(!report.test262_commit.is_empty());

    // Check that we have some distribution of results
    assert!(
        report.overall.passed
            + report.overall.failed
            + report.overall.skipped
            + report.overall.errored
            == report.overall.total_tests
    );

    // Check pass rate calculation
    let expected_pass_rate = (report.overall.passed * MILLIONTHS) / report.overall.total_tests;
    assert_eq!(report.overall.pass_rate_millionths, expected_pass_rate);
}

#[test]
fn test_runner_deterministic_simulation() {
    let config = RunnerConfig {
        max_tests: 5,
        ..RunnerConfig::default()
    };
    let runner1 = Test262Runner::new(config.clone());
    let runner2 = Test262Runner::new(config);
    let epoch = SecurityEpoch::from_raw(1);

    let report1 = runner1.run_conformance(epoch).unwrap();
    let report2 = runner2.run_conformance(epoch).unwrap();

    // Results should be deterministic
    assert_eq!(report1.overall.total_tests, report2.overall.total_tests);
    assert_eq!(report1.overall.passed, report2.overall.passed);
    assert_eq!(report1.overall.failed, report2.overall.failed);
    assert_eq!(report1.overall.skipped, report2.overall.skipped);
    assert_eq!(report1.overall.errored, report2.overall.errored);

    // Test records should match
    for (r1, r2) in report1.test_records.iter().zip(report2.test_records.iter()) {
        assert_eq!(r1.result, r2.result);
        assert_eq!(r1.category, r2.category);
    }
}

#[test]
fn test_runner_unlimited_tests() {
    let config = RunnerConfig {
        max_tests: 0, // Unlimited
        ..RunnerConfig::default()
    };
    let runner = Test262Runner::new(config);
    let epoch = SecurityEpoch::from_raw(1);

    let result = runner.run_conformance(epoch);
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.overall.total_tests, report.total_discovered);
    assert!(!report.is_sample);
}

#[test]
fn test_serde_roundtrip_test_result() {
    let results = [
        TestResult::Pass,
        TestResult::Fail,
        TestResult::Skip,
        TestResult::Error,
    ];
    for result in results {
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: TestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}

#[test]
fn test_serde_roundtrip_test_category() {
    let categories = [
        TestCategory::Language,
        TestCategory::BuiltIns,
        TestCategory::Intl,
        TestCategory::Annexes,
        TestCategory::Harness,
    ];
    for category in categories {
        let json = serde_json::to_string(&category).unwrap();
        let deserialized: TestCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(category, deserialized);
    }
}

#[test]
fn test_serde_roundtrip_test_record() {
    let record = TestRecord::new(
        PathBuf::from("test/example.js"),
        TestResult::Fail,
        1500,
        Some("Test error".to_string()),
        true,
    );

    let json = serde_json::to_string(&record).unwrap();
    let deserialized: TestRecord = serde_json::from_str(&json).unwrap();

    assert_eq!(record.path, deserialized.path);
    assert_eq!(record.category, deserialized.category);
    assert_eq!(record.result, deserialized.result);
    assert_eq!(record.duration_us, deserialized.duration_us);
    assert_eq!(record.error_message, deserialized.error_message);
    assert_eq!(record.is_negative, deserialized.is_negative);
}

#[test]
fn test_serde_roundtrip_test_statistics() {
    let stats = TestStatistics {
        total_tests: 100,
        passed: 60,
        failed: 25,
        skipped: 10,
        errored: 5,
        pass_rate_millionths: 600_000,
        total_duration_us: 50000,
    };

    let json = serde_json::to_string(&stats).unwrap();
    let deserialized: TestStatistics = serde_json::from_str(&json).unwrap();

    assert_eq!(stats.total_tests, deserialized.total_tests);
    assert_eq!(stats.passed, deserialized.passed);
    assert_eq!(stats.failed, deserialized.failed);
    assert_eq!(stats.skipped, deserialized.skipped);
    assert_eq!(stats.errored, deserialized.errored);
    assert_eq!(
        stats.pass_rate_millionths,
        deserialized.pass_rate_millionths
    );
    assert_eq!(stats.total_duration_us, deserialized.total_duration_us);
}

#[test]
fn test_serde_roundtrip_conformance_report() {
    let epoch = SecurityEpoch::from_raw(42);
    let records = vec![
        TestRecord::new(PathBuf::from("a.js"), TestResult::Pass, 100, None, false),
        TestRecord::new(
            PathBuf::from("b.js"),
            TestResult::Fail,
            200,
            Some("error".to_string()),
            false,
        ),
    ];

    let report = ConformanceReport::new(epoch, "abc123".to_string(), records, 1000, true);

    let json = serde_json::to_string(&report).unwrap();
    let deserialized: ConformanceReport = serde_json::from_str(&json).unwrap();

    assert_eq!(report.schema_version, deserialized.schema_version);
    assert_eq!(report.component, deserialized.component);
    assert_eq!(report.bead_id, deserialized.bead_id);
    assert_eq!(report.security_epoch, deserialized.security_epoch);
    assert_eq!(report.test262_commit, deserialized.test262_commit);
    assert_eq!(report.total_discovered, deserialized.total_discovered);
    assert_eq!(report.is_sample, deserialized.is_sample);
    assert_eq!(report.overall.total_tests, deserialized.overall.total_tests);
    assert_eq!(report.test_records.len(), deserialized.test_records.len());
}

#[test]
fn test_json_field_names() {
    let record = TestRecord::new(
        PathBuf::from("test.js"),
        TestResult::Pass,
        1000,
        None,
        false,
    );

    let json = serde_json::to_string(&record).unwrap();
    assert!(json.contains("\"path\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"result\""));
    assert!(json.contains("\"duration_us\""));
    assert!(json.contains("\"error_message\""));
    assert!(json.contains("\"is_negative\""));
}
