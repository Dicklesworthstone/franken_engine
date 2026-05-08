//! Shadow daemon replay verification smoke test integration.
//!
//! This integration test verifies that shadow replay functionality works end-to-end
//! and exits non-zero on nondeterminism or missing provenance as required by bd-djejh.5.

use frankenengine_engine::shadow_replay_fixtures::*;
use frankenengine_engine::shadow_replay_verifier::{ShadowReplayVerifier, ReplayConfig};

/// Smoke test that exits non-zero on nondeterminism or missing provenance.
/// This test ensures the replay verification system works as required.
#[test]
fn shadow_replay_smoke_test() {
    println!("🧪 Starting shadow replay verification smoke test...");

    let mut verifier = ShadowReplayVerifier::with_default_config();

    // Test fixtures for healthy, degraded, contaminated, and stale-source journals
    let test_cases = vec![
        ("healthy", create_healthy_journal_fixture()),
        ("degraded", create_degraded_journal_fixture()),
        ("contaminated", create_contaminated_journal_fixture()),
        ("stale_source", create_stale_source_journal_fixture()),
    ];

    let mut total_tests = 0;
    let mut successful_replays = 0;
    let mut expected_failures = 0;

    for (case_name, export) in test_cases {
        total_tests += 1;
        println!("  📋 Testing {} journal fixture...", case_name);

        // Replay the export
        match verifier.replay_export(export.clone(), format!("smoke_test_{}", case_name)) {
            Ok(report) => {
                successful_replays += 1;

                // Verify report has valid provenance
                assert!(!report.replay_recipe.input_checkpoint.is_empty(),
                       "Missing provenance in {} fixture replay recipe", case_name);
                assert!(!report.replay_recipe.replay_command.is_empty(),
                       "Missing replay command in {} fixture", case_name);
                assert!(!report.replay_recipe.referenced_artifacts.is_empty(),
                       "Missing referenced artifacts in {} fixture", case_name);

                // Verify report structure
                assert!(!report.report_id.to_string().is_empty(),
                       "Missing report ID for {} fixture", case_name);
                assert!(report.detection_timestamp_ms > 0,
                       "Invalid timestamp for {} fixture", case_name);

                // Test determinism by replaying twice
                let second_result = verifier.replay_export(export, format!("smoke_test_{}_repeat", case_name));
                match second_result {
                    Ok(second_report) => {
                        // Verify deterministic behavior
                        assert_eq!(report.detected_drift.len(), second_report.detected_drift.len(),
                                  "Non-deterministic drift count in {} fixture", case_name);
                        assert_eq!(report.is_expected_migration, second_report.is_expected_migration,
                                  "Non-deterministic migration flag in {} fixture", case_name);
                    }
                    Err(e) => {
                        panic!("Non-deterministic behavior: {} fixture succeeded first time but failed second time: {}", case_name, e);
                    }
                }

                println!("    ✓ {} journal: replay successful, {} drift items detected",
                         case_name, report.detected_drift.len());

                // For contaminated fixtures, expect drift detection
                if case_name == "contaminated" {
                    assert!(!report.detected_drift.is_empty(),
                           "Contaminated fixture should detect drift but found none");
                    assert!(!report.is_expected_migration,
                           "Contaminated fixture should not be considered expected migration");
                }

                // Verify schema version consistency
                assert_eq!(report.source_export.schema_version, export.schema_version,
                          "Schema version mismatch in {} fixture", case_name);
            }
            Err(e) => {
                // Some fixtures (especially contaminated) may legitimately fail
                if case_name == "contaminated" {
                    expected_failures += 1;
                    println!("    ✓ {} journal: expected failure detected: {}", case_name, e);
                } else {
                    panic!("Unexpected failure for {} fixture: {}", case_name, e);
                }
            }
        }
    }

    println!("🧪 Smoke test summary:");
    println!("  📊 Total test cases: {}", total_tests);
    println!("  ✅ Successful replays: {}", successful_replays);
    println!("  ⚠️  Expected failures: {}", expected_failures);

    // Ensure we had some successful tests
    assert!(successful_replays > 0, "No successful replays - this indicates a systemic issue");

    // Ensure proper coverage
    assert!(total_tests >= 4, "Expected at least 4 test fixtures");

    println!("✅ Shadow replay verification smoke test passed!");
}

/// Test replay configuration validation.
#[test]
fn test_replay_config_smoke() {
    println!("🔧 Testing replay configuration...");

    // Test default config
    let default_config = ReplayConfig::default();
    assert!(default_config.max_events_per_batch > 0);
    assert!(default_config.replay_timeout_ms > 0);
    assert!(default_config.verify_payload_hashes);
    assert!(default_config.require_deterministic_ordering);

    // Test custom config
    let custom_config = ReplayConfig {
        max_events_per_batch: 500,
        replay_timeout_ms: 15_000,
        allow_schema_migration: false,
        freshness_tolerance_ms: 2000,
        verify_payload_hashes: true,
        require_deterministic_ordering: false,
    };

    let verifier = ShadowReplayVerifier::new(custom_config, 600);
    assert_eq!(verifier.config.max_events_per_batch, 500);
    assert_eq!(verifier.config.replay_timeout_ms, 15_000);
    assert!(!verifier.config.allow_schema_migration);

    println!("✅ Replay configuration validation passed!");
}

/// Test that replay recipes contain exact input artifacts and commands.
#[test]
fn test_replay_recipe_completeness() {
    println!("📋 Testing replay recipe completeness...");

    let mut verifier = ShadowReplayVerifier::with_default_config();
    let export = create_healthy_journal_fixture();

    let result = verifier.replay_export(export, "recipe_test".to_string()).unwrap();
    let recipe = &result.replay_recipe;

    // Verify recipe completeness
    assert!(!recipe.input_checkpoint.is_empty(), "Recipe missing input checkpoint");
    assert!(!recipe.replay_command.is_empty(), "Recipe missing replay command");
    assert!(!recipe.environment_vars.is_empty(), "Recipe missing environment variables");
    assert!(!recipe.expected_outputs.is_empty(), "Recipe missing expected outputs");
    assert!(!recipe.referenced_artifacts.is_empty(), "Recipe missing referenced artifacts");

    // Verify command structure
    assert!(recipe.replay_command.contains(&"cargo".to_string()),
           "Recipe should contain cargo command");
    assert!(recipe.replay_command.contains(&"test".to_string()),
           "Recipe should contain test command");
    assert!(recipe.replay_command.contains(&"frankenengine-engine".to_string()),
           "Recipe should target frankenengine-engine package");

    // Verify environment variables include required ones
    assert!(recipe.environment_vars.contains_key("RUST_BACKTRACE"),
           "Recipe should include RUST_BACKTRACE");
    assert!(recipe.environment_vars.contains_key("TARGET_ENV"),
           "Recipe should include TARGET_ENV");

    // Verify referenced artifacts include core replay components
    let artifacts_str = recipe.referenced_artifacts.join(",");
    assert!(artifacts_str.contains("shadow_replay_verifier.rs"),
           "Recipe should reference shadow_replay_verifier.rs");
    assert!(artifacts_str.contains("shadow_decision_composer.rs"),
           "Recipe should reference shadow_decision_composer.rs");

    println!("✅ Replay recipe completeness test passed!");
}