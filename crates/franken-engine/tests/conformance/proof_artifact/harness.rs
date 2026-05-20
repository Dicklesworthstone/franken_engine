/*!
 * Conformance Harness Infrastructure
 *
 * Core test runner and infrastructure for proof-artifact contract conformance.
 */

use super::*;
use std::time::Instant;

pub struct ConformanceHarness {
    tests: Vec<Box<dyn ConformanceTest>>,
    config: ConformanceConfig,
}

impl ConformanceHarness {
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
            config: ConformanceConfig::default(),
        }
    }

    pub fn with_config(mut self, config: ConformanceConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_test<T: ConformanceTest + 'static>(mut self, test: T) -> Self {
        self.tests.push(Box::new(test));
        self
    }

    /// Register all proof-artifact contract tests
    pub fn register_all_tests(self) -> Self {
        self
            // Schema validation tests
            .add_test(tests::ManifestSchemaTest::new())
            .add_test(tests::EventSchemaTest::new())
            .add_test(tests::ReportSchemaTest::new())
            .add_test(tests::RedactionSchemaTest::new())
            // Required fields tests
            .add_test(tests::ManifestRequiredFieldsTest::new())
            .add_test(tests::EventRequiredFieldsTest::new())
            .add_test(tests::ArtifactPathsTest::new())
            // Validation logic tests
            .add_test(tests::PathNormalizationTest::new())
            .add_test(tests::Sha256ValidationTest::new())
            .add_test(tests::JsonDepthLimitTest::new())
            .add_test(tests::JsonSizeLimitTest::new())
            .add_test(tests::JsonStringLengthTest::new())
            // Hash integrity tests
            .add_test(tests::HashChainIntegrityTest::new())
            .add_test(tests::ArtifactHashTest::new())
            // Bundle structure tests
            .add_test(tests::BundleStructureTest::new())
            .add_test(tests::RequiredArtifactRolesTest::new())
            // Redaction compliance tests
            .add_test(tests::RedactionPolicyTest::new())
            .add_test(tests::SecretDetectionTest::new())
            // Edge cases
            .add_test(tests::EmptyBundleTest::new())
            .add_test(tests::LargeBundleTest::new())
            .add_test(tests::CorruptedArtifactTest::new())
            // Round-trip serialization
            .add_test(tests::ManifestRoundTripTest::new())
            .add_test(tests::EventRoundTripTest::new())
    }

    /// Run all conformance tests and generate report
    pub fn run(&self, fixtures_dir: impl AsRef<Path>) -> ConformanceReport {
        let ctx = TestContext {
            fixtures_dir: fixtures_dir.as_ref().to_path_buf(),
            temp_dir: None,
            config: self.config.clone(),
        };

        let mut results = Vec::new();
        let start_time = Instant::now();

        println!(
            "Running {} proof-artifact conformance tests...\n",
            self.tests.len()
        );

        for test in &self.tests {
            let test_start = Instant::now();
            let result = test.run(&ctx);
            let duration_ms = test_start.elapsed().as_millis() as u64;

            let status_str = match &result {
                TestResult::Pass => "PASS",
                TestResult::Fail { .. } => "FAIL",
                TestResult::Skipped { .. } => "SKIP",
                TestResult::ExpectedFailure { .. } => "XFAIL",
            };

            println!(
                "{:<50} [{:>6}] ({} ms)",
                test.name(),
                status_str,
                duration_ms
            );

            if let TestResult::Fail { reason } = &result {
                println!("  └─ {}", reason);
            }

            results.push(ConformanceResult {
                test_name: test.name().to_string(),
                requirement_id: test.requirement_id().to_string(),
                requirement_level: test.requirement_level(),
                category: test.category(),
                result,
                duration_ms,
            });
        }

        let total_duration = start_time.elapsed();
        println!("\nTotal time: {:.2}s\n", total_duration.as_secs_f64());

        self.generate_report(results)
    }

    fn generate_report(&self, results: Vec<ConformanceResult>) -> ConformanceReport {
        let mut coverage_by_section = BTreeMap::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut skipped = 0;
        let mut xfail = 0;

        for result in &results {
            match &result.result {
                TestResult::Pass => passed += 1,
                TestResult::Fail { .. } => failed += 1,
                TestResult::Skipped { .. } => skipped += 1,
                TestResult::ExpectedFailure { .. } => xfail += 1,
            }

            // Extract section from requirement ID (e.g., "CD3D2B4D-3.1" -> "3")
            let section = result
                .requirement_id
                .split('-')
                .nth(1)
                .and_then(|s| s.split('.').next())
                .unwrap_or("unknown")
                .to_string();

            let stats = coverage_by_section.entry(section).or_default();

            match result.requirement_level {
                RequirementLevel::Must => stats.must_total += 1,
                RequirementLevel::Should => stats.should_total += 1,
                RequirementLevel::May => stats.may_total += 1,
            }

            if matches!(&result.result, TestResult::Pass) {
                stats.passing += 1;
            }
            if matches!(&result.result, TestResult::ExpectedFailure { .. }) {
                stats.xfail += 1;
            }
        }

        let total_tests = results.len() as u32;

        // Calculate overall score: (passed + xfail) / total for MUST clauses primarily
        let must_tests: u32 = results
            .iter()
            .filter(|r| matches!(r.requirement_level, RequirementLevel::Must))
            .count() as u32;

        let must_passed: u32 = results
            .iter()
            .filter(|r| {
                matches!(r.requirement_level, RequirementLevel::Must)
                    && matches!(
                        r.result,
                        TestResult::Pass | TestResult::ExpectedFailure { .. }
                    )
            })
            .count() as u32;

        let overall_score = if must_tests > 0 {
            must_passed as f64 / must_tests as f64
        } else {
            1.0
        };

        ConformanceReport {
            total_tests,
            passed,
            failed,
            skipped,
            xfail,
            coverage_by_section,
            results,
            overall_score,
        }
    }
}
