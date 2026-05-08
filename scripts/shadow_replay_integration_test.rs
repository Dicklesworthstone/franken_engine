#!/usr/bin/env cargo
//! Integration script for shadow daemon replay verification.
//!
//! Validates deterministic replay and drift detection capabilities.
//! Exits non-zero on nondeterminism or missing provenance.

use std::process;

use frankenengine_engine::shadow_replay_fixtures::{
    create_healthy_journal_fixture, create_degraded_journal_fixture,
    create_contaminated_journal_fixture, create_stale_source_journal_fixture,
    create_mixed_state_journal_fixture,
};
use frankenengine_engine::shadow_replay_verifier::{
    ShadowReplayVerifier, ReplayConfig, DriftType,
};

fn main() {
    println!("=== Shadow Daemon Replay Integration Test ===");

    let mut exit_code = 0;

    // Test healthy journal replay
    match test_healthy_journal_replay() {
        Ok(_) => println!("✓ Healthy journal replay: PASS"),
        Err(e) => {
            eprintln!("✗ Healthy journal replay: FAIL - {}", e);
            exit_code = 1;
        }
    }

    // Test contaminated journal drift detection
    match test_contaminated_journal_drift() {
        Ok(_) => println!("✓ Contaminated journal drift detection: PASS"),
        Err(e) => {
            eprintln!("✗ Contaminated journal drift detection: FAIL - {}", e);
            exit_code = 1;
        }
    }

    // Test deterministic replay ordering
    match test_deterministic_replay_ordering() {
        Ok(_) => println!("✓ Deterministic replay ordering: PASS"),
        Err(e) => {
            eprintln!("✗ Deterministic replay ordering: FAIL - {}", e);
            exit_code = 1;
        }
    }

    // Test provenance verification
    match test_provenance_verification() {
        Ok(_) => println!("✓ Provenance verification: PASS"),
        Err(e) => {
            eprintln!("✗ Provenance verification: FAIL - {}", e);
            exit_code = 1;
        }
    }

    if exit_code == 0 {
        println!("=== All shadow replay tests PASSED ===");
    } else {
        println!("=== Shadow replay tests FAILED ===");
    }

    process::exit(exit_code);
}

fn test_healthy_journal_replay() -> Result<(), String> {
    let mut verifier = ShadowReplayVerifier::with_default_config();
    let fixture = create_healthy_journal_fixture();

    let report = verifier.replay_export(fixture, "integration_test".to_string())
        .map_err(|e| format!("Replay failed: {}", e))?;

    // Healthy journal should have no drift
    if !report.detected_drift.is_empty() {
        return Err(format!("Unexpected drift detected: {:?}", report.detected_drift));
    }

    // Should not be flagged as migration
    if report.is_expected_migration {
        return Err("Healthy journal incorrectly flagged as migration".to_string());
    }

    // Should have replay recipe
    if report.replay_recipe.replay_command.is_empty() {
        return Err("Missing replay recipe".to_string());
    }

    Ok(())
}

fn test_contaminated_journal_drift() -> Result<(), String> {
    let mut verifier = ShadowReplayVerifier::with_default_config();
    let fixture = create_contaminated_journal_fixture();

    let report = verifier.replay_export(fixture, "integration_test".to_string())
        .map_err(|e| format!("Replay failed: {}", e))?;

    // Contaminated journal should have drift
    if report.detected_drift.is_empty() {
        return Err("No drift detected in contaminated journal".to_string());
    }

    // Should detect payload hash mismatches
    let has_payload_mismatch = report.detected_drift.iter().any(|drift| {
        matches!(drift, DriftType::PayloadHashMismatch { .. })
    });

    if !has_payload_mismatch {
        return Err("Expected payload hash mismatch not detected".to_string());
    }

    // Should not be flagged as expected migration
    if report.is_expected_migration {
        return Err("Contaminated journal incorrectly flagged as expected migration".to_string());
    }

    Ok(())
}

fn test_deterministic_replay_ordering() -> Result<(), String> {
    let mut verifier1 = ShadowReplayVerifier::with_default_config();
    let mut verifier2 = ShadowReplayVerifier::with_default_config();

    let fixture = create_mixed_state_journal_fixture();

    let report1 = verifier1.replay_export(fixture.clone(), "test1".to_string())
        .map_err(|e| format!("First replay failed: {}", e))?;

    let report2 = verifier2.replay_export(fixture, "test2".to_string())
        .map_err(|e| format!("Second replay failed: {}", e))?;

    // Reports should be deterministic (same detection results)
    if report1.detected_drift.len() != report2.detected_drift.len() {
        return Err("Non-deterministic drift detection count".to_string());
    }

    // Both reports should have the same migration status
    if report1.is_expected_migration != report2.is_expected_migration {
        return Err("Non-deterministic migration status".to_string());
    }

    Ok(())
}

fn test_provenance_verification() -> Result<(), String> {
    let mut verifier = ShadowReplayVerifier::with_default_config();
    let fixture = create_stale_source_journal_fixture();

    let report = verifier.replay_export(fixture, "provenance_test".to_string())
        .map_err(|e| format!("Replay failed: {}", e))?;

    // Should have provenance information in replay recipe
    if report.replay_recipe.referenced_artifacts.is_empty() {
        return Err("Missing provenance artifacts in replay recipe".to_string());
    }

    // Should reference key source files
    let has_verifier_ref = report.replay_recipe.referenced_artifacts.iter()
        .any(|artifact| artifact.contains("shadow_replay_verifier.rs"));

    if !has_verifier_ref {
        return Err("Missing shadow_replay_verifier.rs in provenance".to_string());
    }

    let has_composer_ref = report.replay_recipe.referenced_artifacts.iter()
        .any(|artifact| artifact.contains("shadow_decision_composer.rs"));

    if !has_composer_ref {
        return Err("Missing shadow_decision_composer.rs in provenance".to_string());
    }

    // Should have environment variables for reproducibility
    if !report.replay_recipe.environment_vars.contains_key("RUST_BACKTRACE") {
        return Err("Missing RUST_BACKTRACE in environment".to_string());
    }

    Ok(())
}