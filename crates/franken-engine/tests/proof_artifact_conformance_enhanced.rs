/*!
 * Enhanced Proof Artifact Contract Conformance Harness
 *
 * Systematic validation of ALL MUST/SHOULD requirements in cd3d2b4d using
 * the testing-conformance-harnesses methodology. Replaces basic conformance
 * with comprehensive coverage accounting and fixture management.
 */

mod conformance {
    pub mod proof_artifact;
}

use conformance::proof_artifact::{fixtures::FixtureManager, harness::ConformanceHarness};
use std::fs;

#[test]
fn comprehensive_proof_artifact_conformance() {
    println!("🔍 Proof Artifact Contract Conformance Harness (Enhanced)");
    println!("Contract: cd3d2b4d proof-artifact specification");
    println!("Methodology: testing-conformance-harnesses systematic validation\n");

    // Create fixtures directory and provenance documentation
    let fixtures_dir = std::env::temp_dir().join("proof_artifact_conformance_fixtures");
    fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures directory");

    let fixture_manager = FixtureManager::new(&fixtures_dir);
    fixture_manager
        .create_provenance_doc()
        .expect("Failed to create provenance documentation");

    // Build and run comprehensive conformance harness
    let harness = ConformanceHarness::new().register_all_tests(); // Register all cd3d2b4d requirements

    let report = harness.run(&fixtures_dir);

    // Generate compliance report
    let markdown_report = report.to_markdown();
    let report_path = fixtures_dir.join("CONFORMANCE_REPORT.md");
    fs::write(&report_path, &markdown_report).expect("Failed to write conformance report");

    println!("{}", markdown_report);

    // Print coverage accounting matrix summary
    println!("📊 Coverage Accounting Matrix:");
    println!("Overall Score: {:.1}%", report.overall_score * 100.0);
    println!("Total Requirements: {}", report.total_tests);
    println!(
        "MUST clause coverage: {:.1}%",
        calculate_must_coverage(&report)
    );

    // Check minimum conformance threshold (95% for MUST clauses)
    let must_score = calculate_must_coverage(&report) / 100.0;
    if must_score < 0.95 {
        panic!(
            "CONFORMANCE FAILURE: MUST clause coverage {:.1}% < 95% threshold. \
             See {} for detailed analysis.",
            must_score * 100.0,
            report_path.display()
        );
    }

    // Fail if any non-XFAIL failures exist
    if report.failed > 0 {
        println!(
            "❌ {} conformance tests failed (excluding expected failures)",
            report.failed
        );
        println!("📋 Detailed failures:");

        for result in &report.results {
            if let conformance::proof_artifact::TestResult::Fail { reason } = &result.result {
                println!("  • {}: {}", result.test_name, reason);
            }
        }

        panic!("Proof artifact contract conformance failures detected");
    }

    println!("✅ Proof artifact contract conformance: ALL TESTS PASS");
    println!("📄 Full report: {}", report_path.display());
    println!("🎉 cd3d2b4d contract implementation is conformant\n");
}

fn calculate_must_coverage(report: &conformance::proof_artifact::ConformanceReport) -> f64 {
    let must_tests: u32 = report
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.requirement_level,
                conformance::proof_artifact::RequirementLevel::Must
            )
        })
        .count() as u32;

    let must_passed: u32 = report
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.requirement_level,
                conformance::proof_artifact::RequirementLevel::Must
            ) && matches!(
                r.result,
                conformance::proof_artifact::TestResult::Pass
                    | conformance::proof_artifact::TestResult::ExpectedFailure { .. }
            )
        })
        .count() as u32;

    if must_tests > 0 {
        (must_passed as f64 / must_tests as f64) * 100.0
    } else {
        100.0
    }
}

#[test]
fn conformance_fixture_integrity() {
    // Test fixture generation itself
    let fixtures_dir = std::env::temp_dir().join("test_fixture_integrity");
    fs::create_dir_all(&fixtures_dir).expect("Failed to create test directory");

    let fixture_manager = FixtureManager::new(&fixtures_dir);

    // Test valid bundle creation
    let valid_bundle = fixture_manager
        .create_valid_bundle()
        .expect("Failed to create valid test bundle");

    assert!(valid_bundle.path().join("manifest.json").exists());
    assert!(valid_bundle.path().join("events.jsonl").exists());
    assert!(valid_bundle.path().join("report.json").exists());

    // Test invalid bundle creation
    let invalid_bundle = fixture_manager
        .create_invalid_schema_bundle()
        .expect("Failed to create invalid test bundle");

    assert!(invalid_bundle.path().join("manifest.json").exists());

    println!("✅ Conformance fixture integrity verified");
}

#[test]
fn conformance_harness_self_test() {
    // Test that the harness infrastructure works correctly
    use conformance::proof_artifact::{
        ConformanceTest, RequirementLevel, TestCategory, TestContext, TestResult,
    };

    struct MockTest;
    impl ConformanceTest for MockTest {
        fn name(&self) -> &str {
            "mock_test"
        }
        fn category(&self) -> TestCategory {
            TestCategory::Unit
        }
        fn requirement_level(&self) -> RequirementLevel {
            RequirementLevel::Must
        }
        fn requirement_id(&self) -> &str {
            "MOCK-1.1"
        }
        fn description(&self) -> &str {
            "Mock test for harness validation"
        }
        fn run(&self, _ctx: &TestContext) -> TestResult {
            TestResult::Pass
        }
    }

    let harness = ConformanceHarness::new().add_test(MockTest);
    let fixtures_dir = std::env::temp_dir().join("harness_self_test");
    fs::create_dir_all(&fixtures_dir).expect("Failed to create test directory");

    let report = harness.run(&fixtures_dir);

    assert_eq!(report.total_tests, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(report.overall_score, 1.0);

    println!("✅ Conformance harness self-test passed");
}
