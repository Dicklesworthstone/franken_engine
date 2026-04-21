//! Test262 Conformance Runner
//!
//! Bead: bd-axlvk.3 - Integrate Test262 runner and publish conformance pass rate
//!
//! Integrates the Test262 JavaScript conformance test suite with franken_engine
//! to measure and track JavaScript compatibility over time. Provides structured
//! reporting of pass/fail/skip/error rates with detailed categorization.
//!
//! Test262 is the official conformance test suite for JavaScript (ECMAScript).
//! This runner executes tests through the full franken_engine pipeline:
//! parse -> lower -> execute, providing concrete metrics for JS compatibility.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use chrono;
use serde::{Deserialize, Serialize};

use crate::HybridRouter;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for Test262 conformance reports.
pub const SCHEMA_VERSION: &str = "franken-engine.test262-conformance-runner.v1";

/// Component name.
pub const COMPONENT: &str = "test262_conformance_runner";

/// Bead reference.
pub const BEAD_ID: &str = "bd-axlvk.3";

/// Default Test262 repository URL.
pub const DEFAULT_TEST262_URL: &str = "https://github.com/tc39/test262.git";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Test execution result classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TestResult {
    /// Test passed successfully.
    Pass,
    /// Test failed with assertion error.
    Fail,
    /// Test skipped due to unsupported syntax.
    Skip,
    /// Test error during parsing/lowering/execution.
    Error,
}

impl TestResult {
    /// Convert to string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            TestResult::Pass => "pass",
            TestResult::Fail => "fail",
            TestResult::Skip => "skip",
            TestResult::Error => "error",
        }
    }

    /// Whether this result indicates successful execution.
    pub fn is_passing(self) -> bool {
        matches!(self, TestResult::Pass)
    }
}

impl fmt::Display for TestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Test category classification for grouping results.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TestCategory {
    /// Language syntax and semantics.
    Language,
    /// Built-in objects and functions.
    BuiltIns,
    /// Internationalization API.
    Intl,
    /// Annexes and optional features.
    Annexes,
    /// Test harness and infrastructure.
    Harness,
}

impl TestCategory {
    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TestCategory::Language => "language",
            TestCategory::BuiltIns => "built-ins",
            TestCategory::Intl => "intl",
            TestCategory::Annexes => "annexes",
            TestCategory::Harness => "harness",
        }
    }

    /// Classify test by file path.
    pub fn from_path(path: &Path) -> Self {
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("language") {
            TestCategory::Language
        } else if path_str.contains("built-ins") || path_str.contains("builtins") {
            TestCategory::BuiltIns
        } else if path_str.contains("intl") {
            TestCategory::Intl
        } else if path_str.contains("annexes") {
            TestCategory::Annexes
        } else if path_str.contains("harness") {
            TestCategory::Harness
        } else {
            TestCategory::Language // Default
        }
    }
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Individual test execution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRecord {
    /// Test file path relative to Test262 root.
    pub path: PathBuf,
    /// Test category classification.
    pub category: TestCategory,
    /// Execution result.
    pub result: TestResult,
    /// Execution time in microseconds.
    pub duration_us: u64,
    /// Error message if result is Error or Fail.
    pub error_message: Option<String>,
    /// Whether test is marked as negative (expected to fail).
    pub is_negative: bool,
}

impl TestRecord {
    /// Create a new test record.
    pub fn new(
        path: PathBuf,
        result: TestResult,
        duration_us: u64,
        error_message: Option<String>,
        is_negative: bool,
    ) -> Self {
        let category = TestCategory::from_path(&path);
        Self {
            path,
            category,
            result,
            duration_us,
            error_message,
            is_negative,
        }
    }
}

/// Aggregated test statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStatistics {
    /// Total number of tests executed.
    pub total_tests: u64,
    /// Number of passing tests.
    pub passed: u64,
    /// Number of failing tests.
    pub failed: u64,
    /// Number of skipped tests.
    pub skipped: u64,
    /// Number of error tests.
    pub errored: u64,
    /// Pass rate in millionths (1_000_000 = 100%).
    pub pass_rate_millionths: u64,
    /// Total execution time in microseconds.
    pub total_duration_us: u64,
}

impl TestStatistics {
    /// Create statistics from test records.
    pub fn from_records(records: &[TestRecord]) -> Self {
        let total_tests = records.len() as u64;
        let passed = records
            .iter()
            .filter(|r| r.result == TestResult::Pass)
            .count() as u64;
        let failed = records
            .iter()
            .filter(|r| r.result == TestResult::Fail)
            .count() as u64;
        let skipped = records
            .iter()
            .filter(|r| r.result == TestResult::Skip)
            .count() as u64;
        let errored = records
            .iter()
            .filter(|r| r.result == TestResult::Error)
            .count() as u64;

        let pass_rate_millionths = (passed * MILLIONTHS).checked_div(total_tests).unwrap_or(0);

        let total_duration_us = records.iter().map(|r| r.duration_us).sum();

        Self {
            total_tests,
            passed,
            failed,
            skipped,
            errored,
            pass_rate_millionths,
            total_duration_us,
        }
    }

    /// Get pass rate as percentage (0.0 to 100.0).
    pub fn pass_rate_percent(&self) -> f64 {
        (self.pass_rate_millionths as f64) / 10_000.0
    }
}

/// Test262 conformance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead ID.
    pub bead_id: String,
    /// Security epoch.
    pub security_epoch: SecurityEpoch,
    /// Report timestamp (RFC 3339).
    pub timestamp: String,
    /// Test262 commit hash used.
    pub test262_commit: String,
    /// Overall statistics.
    pub overall: TestStatistics,
    /// Statistics by category.
    pub by_category: BTreeMap<TestCategory, TestStatistics>,
    /// Individual test records (sample for large runs).
    pub test_records: Vec<TestRecord>,
    /// Total tests discovered (may be larger than executed).
    pub total_discovered: u64,
    /// Whether this is a sample run (not all tests executed).
    pub is_sample: bool,
}

impl ConformanceReport {
    /// Create a new conformance report.
    pub fn new(
        security_epoch: SecurityEpoch,
        test262_commit: String,
        records: Vec<TestRecord>,
        total_discovered: u64,
        is_sample: bool,
    ) -> Self {
        let overall = TestStatistics::from_records(&records);

        // Group by category
        let mut by_category = BTreeMap::new();
        for category in [
            TestCategory::Language,
            TestCategory::BuiltIns,
            TestCategory::Intl,
            TestCategory::Annexes,
            TestCategory::Harness,
        ] {
            let category_records: Vec<_> = records
                .iter()
                .filter(|r| r.category == category)
                .cloned()
                .collect();
            let stats = TestStatistics::from_records(&category_records);
            by_category.insert(category, stats);
        }

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            security_epoch,
            timestamp: chrono::Utc::now().to_rfc3339(),
            test262_commit,
            overall,
            by_category,
            test_records: records,
            total_discovered,
            is_sample,
        }
    }
}

/// Test262 conformance runner configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerConfig {
    /// Path to Test262 repository.
    pub test262_path: PathBuf,
    /// Maximum number of tests to execute (0 = all).
    pub max_tests: usize,
    /// Test pattern filter (glob).
    pub pattern: Option<String>,
    /// Include negative tests.
    pub include_negative: bool,
    /// Timeout per test in milliseconds.
    pub timeout_ms: u64,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            test262_path: PathBuf::from("test262"),
            max_tests: 1000, // Start with sample
            pattern: None,
            include_negative: true,
            timeout_ms: 5000,
        }
    }
}

/// Test262 conformance runner.
pub struct Test262Runner {
    config: RunnerConfig,
}

#[derive(Debug, Clone)]
struct DiscoveredTest {
    report_path: PathBuf,
    source: Option<String>,
    discovery_error: Option<String>,
    is_negative: bool,
}

#[derive(Debug, Default, Clone)]
struct TestMetadata {
    is_negative: bool,
}

impl Test262Runner {
    /// Create a new Test262 runner.
    pub fn new(config: RunnerConfig) -> Self {
        Self { config }
    }

    /// Execute Test262 conformance suite.
    pub fn run_conformance(
        &self,
        security_epoch: SecurityEpoch,
    ) -> Result<ConformanceReport, String> {
        let discovered_tests = self.discover_tests()?;
        if discovered_tests.is_empty() {
            return Err(format!(
                "no Test262 .js fixtures discovered under {}",
                self.config.test262_path.display()
            ));
        }

        let total_discovered = discovered_tests.len() as u64;
        let max_tests = if self.config.max_tests == 0 {
            discovered_tests.len()
        } else {
            self.config.max_tests.min(discovered_tests.len())
        };

        let records: Vec<_> = discovered_tests
            .iter()
            .take(max_tests)
            .map(|test| self.execute_test(test, security_epoch))
            .collect();

        let test262_commit = self.resolve_test262_revision(&discovered_tests);
        let is_sample = records.len() < discovered_tests.len();

        let report = ConformanceReport::new(
            security_epoch,
            test262_commit,
            records,
            total_discovered,
            is_sample,
        );

        Ok(report)
    }

    fn discover_tests(&self) -> Result<Vec<DiscoveredTest>, String> {
        let test_root = self.test_root()?;
        let mut js_files = Vec::new();
        collect_js_files(&test_root, &mut js_files)?;
        js_files.sort();

        let mut discovered = Vec::new();
        for absolute_path in js_files {
            let report_path = absolute_path
                .strip_prefix(&self.config.test262_path)
                .unwrap_or(absolute_path.as_path())
                .to_path_buf();
            if !self.matches_pattern(&report_path) {
                continue;
            }

            let (source, discovery_error, metadata) = match fs::read_to_string(&absolute_path) {
                Ok(source) => {
                    let metadata = parse_test262_metadata(&source);
                    (Some(source), None, metadata)
                }
                Err(error) => (
                    None,
                    Some(format!(
                        "failed to read {}: {error}",
                        absolute_path.display()
                    )),
                    TestMetadata::default(),
                ),
            };

            if metadata.is_negative && !self.config.include_negative {
                continue;
            }

            discovered.push(DiscoveredTest {
                report_path,
                source,
                discovery_error,
                is_negative: metadata.is_negative,
            });
        }

        Ok(discovered)
    }

    fn test_root(&self) -> Result<PathBuf, String> {
        if !self.config.test262_path.is_dir() {
            return Err(format!(
                "Test262 path does not exist or is not a directory: {}",
                self.config.test262_path.display()
            ));
        }

        let nested_test_dir = self.config.test262_path.join("test");
        if nested_test_dir.is_dir() {
            Ok(nested_test_dir)
        } else {
            Ok(self.config.test262_path.clone())
        }
    }

    fn matches_pattern(&self, path: &Path) -> bool {
        let Some(pattern) = self.config.pattern.as_deref() else {
            return true;
        };

        path_matches_pattern(path, pattern)
    }

    /// Execute a single discovered fixture through the native eval pipeline.
    fn execute_test(&self, test: &DiscoveredTest, _security_epoch: SecurityEpoch) -> TestRecord {
        let start_time = Instant::now();

        let (result, error_message) = if let Some(discovery_error) = test.discovery_error.as_deref()
        {
            (TestResult::Error, Some(discovery_error.to_string()))
        } else if let Some(source) = test.source.as_deref() {
            let mut engine = HybridRouter::default();
            match engine.eval(source) {
                Ok(_) if test.is_negative => (
                    TestResult::Fail,
                    Some("negative Test262 fixture unexpectedly evaluated successfully".into()),
                ),
                Ok(_) => (TestResult::Pass, None),
                Err(error) if test.is_negative => (TestResult::Pass, Some(error.to_string())),
                Err(error) => (
                    TestResult::Error,
                    Some(format!("engine evaluation failed: {error}")),
                ),
            }
        } else {
            (
                TestResult::Error,
                Some("missing discovered source and discovery error".to_string()),
            )
        };

        let duration_us = start_time.elapsed().as_micros() as u64;
        let (result, error_message) =
            if self.config.timeout_ms > 0 && duration_us / 1_000 > self.config.timeout_ms {
                (
                    TestResult::Error,
                    Some(format!(
                        "test exceeded timeout: {}ms > {}ms",
                        duration_us / 1_000,
                        self.config.timeout_ms
                    )),
                )
            } else {
                (result, error_message)
            };

        TestRecord::new(
            test.report_path.clone(),
            result,
            duration_us,
            error_message,
            test.is_negative,
        )
    }

    fn resolve_test262_revision(&self, discovered_tests: &[DiscoveredTest]) -> String {
        if let Ok(output) = Command::new("git")
            .arg("-C")
            .arg(&self.config.test262_path)
            .arg("rev-parse")
            .arg("HEAD")
            .output()
        {
            if output.status.success() {
                let revision = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !revision.is_empty() {
                    return revision;
                }
            }
        }

        let mut digest_input = Vec::new();
        for test in discovered_tests {
            digest_input.extend_from_slice(test.report_path.to_string_lossy().as_bytes());
            digest_input.push(0);
            if let Some(source) = test.source.as_deref() {
                digest_input.extend_from_slice(source.as_bytes());
            }
            digest_input.push(0xff);
        }
        format!(
            "content-sha256:{}",
            ContentHash::compute(&digest_input).to_hex()
        )
    }
}

fn collect_js_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(root)
        .map_err(|error| format!("failed to read {}: {error}", root.display()))?;

    for entry in entries {
        let entry = entry
            .map_err(|error| format!("failed to read entry in {}: {error}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to stat {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_js_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "js") {
            files.push(path);
        }
    }

    Ok(())
}

fn path_matches_pattern(path: &Path, pattern: &str) -> bool {
    let normalized_path = path.to_string_lossy().replace('\\', "/");
    let pattern = pattern.trim().replace('\\', "/");
    if pattern.is_empty() || pattern == "*.js" || pattern == "**/*.js" {
        return true;
    }
    if !pattern.contains('*') {
        return normalized_path.contains(&pattern);
    }

    let mut cursor = 0;
    for fragment in pattern.split('*').filter(|fragment| !fragment.is_empty()) {
        let Some(offset) = normalized_path[cursor..].find(fragment) else {
            return false;
        };
        cursor += offset + fragment.len();
    }
    true
}

fn parse_test262_metadata(source: &str) -> TestMetadata {
    let metadata_block = source
        .find("/*---")
        .and_then(|start| {
            source[start..]
                .find("---*/")
                .map(|end| &source[start..(start + end)])
        })
        .unwrap_or("");

    TestMetadata {
        is_negative: metadata_block
            .lines()
            .any(|line| line.trim_start().starts_with("negative:")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_result_as_str() {
        assert_eq!(TestResult::Pass.as_str(), "pass");
        assert_eq!(TestResult::Fail.as_str(), "fail");
        assert_eq!(TestResult::Skip.as_str(), "skip");
        assert_eq!(TestResult::Error.as_str(), "error");
    }

    #[test]
    fn test_result_is_passing() {
        assert!(TestResult::Pass.is_passing());
        assert!(!TestResult::Fail.is_passing());
        assert!(!TestResult::Skip.is_passing());
        assert!(!TestResult::Error.is_passing());
    }

    #[test]
    fn test_category_from_path() {
        assert_eq!(
            TestCategory::from_path(Path::new("test/language/expr.js")),
            TestCategory::Language
        );
        assert_eq!(
            TestCategory::from_path(Path::new("test/built-ins/Array.js")),
            TestCategory::BuiltIns
        );
        assert_eq!(
            TestCategory::from_path(Path::new("test/intl/Locale.js")),
            TestCategory::Intl
        );
        assert_eq!(
            TestCategory::from_path(Path::new("test/annexes/b/regexp.js")),
            TestCategory::Annexes
        );
        assert_eq!(
            TestCategory::from_path(Path::new("test/harness/assert.js")),
            TestCategory::Harness
        );
    }

    #[test]
    fn test_statistics_from_records() {
        let records = vec![
            TestRecord::new(PathBuf::from("a.js"), TestResult::Pass, 100, None, false),
            TestRecord::new(PathBuf::from("b.js"), TestResult::Pass, 200, None, false),
            TestRecord::new(
                PathBuf::from("c.js"),
                TestResult::Fail,
                150,
                Some("error".to_string()),
                false,
            ),
            TestRecord::new(PathBuf::from("d.js"), TestResult::Skip, 50, None, false),
            TestRecord::new(
                PathBuf::from("e.js"),
                TestResult::Error,
                300,
                Some("parse error".to_string()),
                false,
            ),
        ];

        let stats = TestStatistics::from_records(&records);
        assert_eq!(stats.total_tests, 5);
        assert_eq!(stats.passed, 2);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.errored, 1);
        assert_eq!(stats.pass_rate_millionths, 400_000); // 40%
        assert_eq!(stats.total_duration_us, 800);
        assert!((stats.pass_rate_percent() - 40.0).abs() < 0.01);
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
    fn test_runner_creation() {
        let config = RunnerConfig::default();
        let runner = Test262Runner::new(config);
        assert_eq!(runner.config.max_tests, 1000);
    }

    #[test]
    fn test_conformance_report_creation() {
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
                PathBuf::from("test/built-ins/b.js"),
                TestResult::Fail,
                200,
                Some("error".to_string()),
                false,
            ),
        ];

        let report = ConformanceReport::new(epoch, "abc123".to_string(), records, 1000, true);

        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.component, COMPONENT);
        assert_eq!(report.bead_id, BEAD_ID);
        assert_eq!(report.security_epoch, epoch);
        assert_eq!(report.test262_commit, "abc123");
        assert_eq!(report.overall.total_tests, 2);
        assert_eq!(report.overall.passed, 1);
        assert_eq!(report.total_discovered, 1000);
        assert!(report.is_sample);
        assert!(report.by_category.contains_key(&TestCategory::Language));
        assert!(report.by_category.contains_key(&TestCategory::BuiltIns));
    }

    #[test]
    fn test_conformance_run_discovers_and_executes_fixture_files() {
        let temp_dir = tempdir().unwrap();
        let test_dir = temp_dir.path().join("test/language/literals");
        fs::create_dir_all(&test_dir).unwrap();
        fs::write(test_dir.join("numeric-literal.js"), "42").unwrap();

        let config = RunnerConfig {
            test262_path: temp_dir.path().to_path_buf(),
            max_tests: 1,
            ..RunnerConfig::default()
        };
        let runner = Test262Runner::new(config);
        let epoch = SecurityEpoch::from_raw(1);

        let result = runner.run_conformance(epoch);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.overall.total_tests, 1);
        assert_eq!(report.total_discovered, 1);
        assert_eq!(report.security_epoch, epoch);
        assert!(!report.is_sample);
        assert_ne!(report.test262_commit, "mock-commit-hash");
        assert_eq!(
            report.test_records[0].path,
            PathBuf::from("test/language/literals/numeric-literal.js")
        );
    }

    #[test]
    fn test_conformance_run_errors_when_fixture_root_is_missing() {
        let config = RunnerConfig {
            test262_path: PathBuf::from("/definitely/missing/test262/root"),
            ..RunnerConfig::default()
        };
        let runner = Test262Runner::new(config);

        let err = runner
            .run_conformance(SecurityEpoch::from_raw(1))
            .unwrap_err();
        assert!(err.contains("Test262 path does not exist"));
    }

    #[test]
    fn test_conformance_run_filters_negative_fixtures_from_real_metadata() {
        let temp_dir = tempdir().unwrap();
        let test_dir = temp_dir.path().join("test/language");
        fs::create_dir_all(&test_dir).unwrap();
        fs::write(test_dir.join("positive.js"), "42").unwrap();
        fs::write(
            test_dir.join("negative.js"),
            "/*---\nnegative:\n  phase: parse\n  type: SyntaxError\n---*/\nlet",
        )
        .unwrap();

        let config = RunnerConfig {
            test262_path: temp_dir.path().to_path_buf(),
            max_tests: 0,
            include_negative: false,
            ..RunnerConfig::default()
        };
        let runner = Test262Runner::new(config);
        let report = runner.run_conformance(SecurityEpoch::from_raw(1)).unwrap();

        assert_eq!(report.overall.total_tests, 1);
        assert_eq!(
            report.test_records[0].path,
            PathBuf::from("test/language/positive.js")
        );
        assert!(!report.test_records[0].is_negative);
    }
}
