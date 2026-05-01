/*!
 * Proof Artifact Conformance Report Generator
 *
 * Standalone binary to generate compliance matrices and coverage reports
 * for the cd3d2b4d proof-artifact contract. Can be run independently
 * of the test suite for CI/CD integration.
 */

use std::env;
use std::fs;
use std::path::PathBuf;

use super::{harness::ConformanceHarness, fixtures::FixtureManager};

/// Generate comprehensive conformance report
pub fn generate_compliance_report(fixtures_dir: Option<PathBuf>) -> Result<String, Box<dyn std::error::Error>> {
    // Use provided fixtures dir or create temp
    let fixtures_dir = fixtures_dir.unwrap_or_else(|| {
        std::env::temp_dir().join("proof_artifact_conformance")
    });

    fs::create_dir_all(&fixtures_dir)?;

    // Create fixtures and provenance
    let fixture_manager = FixtureManager::new(&fixtures_dir);
    fixture_manager.create_provenance_doc()?;

    // Build comprehensive harness
    let harness = ConformanceHarness::new()
        .register_all_tests();

    // Run all tests
    let report = harness.run(&fixtures_dir);

    // Generate markdown report
    let markdown = report.to_markdown();

    // Write to file
    let report_path = fixtures_dir.join("CONFORMANCE_REPORT.md");
    fs::write(&report_path, &markdown)?;

    println!("📄 Compliance report written to: {}", report_path.display());

    // Print summary to stdout
    println!("\n📊 COMPLIANCE SUMMARY");
    println!("Overall Score: {:.1}%", report.overall_score * 100.0);
    println!("Tests: {} total, {} passed, {} failed, {} xfail",
        report.total_tests, report.passed, report.failed, report.xfail);

    let must_coverage = calculate_must_coverage(&report);
    println!("MUST clause coverage: {:.1}%", must_coverage);

    if must_coverage < 95.0 {
        println!("⚠️  WARNING: MUST clause coverage below 95% threshold");
    }

    if report.failed > 0 {
        println!("❌ CONFORMANCE FAILURES DETECTED");
        for result in &report.results {
            if let crate::conformance::proof_artifact::TestResult::Fail { reason } = &result.result {
                println!("  • {}: {}", result.test_name, reason);
            }
        }
    } else {
        println!("✅ ALL CONFORMANCE TESTS PASS");
    }

    Ok(markdown)
}

fn calculate_must_coverage(report: &crate::conformance::proof_artifact::ConformanceReport) -> f64 {
    let must_tests: u32 = report
        .results
        .iter()
        .filter(|r| matches!(
            r.requirement_level,
            crate::conformance::proof_artifact::RequirementLevel::Must
        ))
        .count() as u32;

    let must_passed: u32 = report
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.requirement_level,
                crate::conformance::proof_artifact::RequirementLevel::Must
            ) && matches!(
                r.result,
                crate::conformance::proof_artifact::TestResult::Pass
                    | crate::conformance::proof_artifact::TestResult::ExpectedFailure { .. }
            )
        })
        .count() as u32;

    if must_tests > 0 {
        (must_passed as f64 / must_tests as f64) * 100.0
    } else {
        100.0
    }
}

/// CLI entry point for standalone report generation
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let fixtures_dir = if args.len() > 1 {
        Some(PathBuf::from(&args[1]))
    } else {
        None
    };

    println!("🔍 Proof Artifact Contract Conformance Report Generator");
    println!("Contract: cd3d2b4d proof-artifact specification\n");

    let _report = generate_compliance_report(fixtures_dir)?;

    Ok(())
}