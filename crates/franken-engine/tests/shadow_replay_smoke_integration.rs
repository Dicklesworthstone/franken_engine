//! Shadow daemon replay verification smoke test integration.
//!
//! This integration test verifies that shadow replay functionality works end-to-end
//! and exits non-zero on nondeterminism or missing provenance as required by bd-djejh.5.

use std::collections::BTreeMap;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::shadow_evidence_journal::{
    SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION, ShadowEvidenceJournalExport,
    ShadowEvidenceJournalExportRow,
};
use frankenengine_engine::shadow_replay_verifier::{ReplayConfig, ShadowReplayVerifier};
use serde_json::{Value, json};

const FIXTURE_BASE_TIMESTAMP_MS: i64 = 1_704_067_200_000;

fn create_healthy_journal_fixture() -> ShadowEvidenceJournalExport {
    create_journal_fixture("healthy", 1000, 5, 1_000, 300_000, false)
}

fn create_degraded_journal_fixture() -> ShadowEvidenceJournalExport {
    create_journal_fixture("degraded", 2000, 4, 5_000, 600_000, false)
}

fn create_contaminated_journal_fixture() -> ShadowEvidenceJournalExport {
    create_journal_fixture("contaminated", 3000, 3, 2_000, 300_000, true)
}

fn create_stale_source_journal_fixture() -> ShadowEvidenceJournalExport {
    create_journal_fixture("stale", 4000, 6, 1_000, 60_000, false)
}

fn create_journal_fixture(
    state: &str,
    first_event_id: i64,
    count: usize,
    interval_ms: i64,
    freshness_window_ms: i64,
    corrupt_normalized_hash: bool,
) -> ShadowEvidenceJournalExport {
    let base_timestamp = if state == "stale" {
        FIXTURE_BASE_TIMESTAMP_MS - 86_400_000
    } else {
        FIXTURE_BASE_TIMESTAMP_MS
    };

    let rows = (0..count)
        .map(|index| {
            let journal_event_id = first_event_id + index as i64;
            let collected_timestamp_ms = base_timestamp + (index as i64 * interval_ms);
            let payload = event_payload(state, index);
            let payload_hash =
                hex_encode(ContentHash::compute(&payload_bytes(&payload)).as_bytes());
            let normalized_payload_hash = if corrupt_normalized_hash {
                corrupt_hex_hash(&payload_hash)
            } else {
                payload_hash.clone()
            };

            let mut metadata = BTreeMap::new();
            metadata.insert("event_index".to_string(), Value::Number(index.into()));
            metadata.insert(
                "journal_state".to_string(),
                Value::String(state.to_string()),
            );
            metadata.insert(
                "expected_decision_hash".to_string(),
                Value::String(expected_decision_hash(&payload)),
            );

            ShadowEvidenceJournalExportRow {
                journal_event_id,
                bead_id: format!("{state}_bead_{index}"),
                event_kind: format!("{state}_event"),
                source_kind: "test_fixture".to_string(),
                source_locator: format!("fixture://{state}/event_{index}"),
                collected_timestamp_ms,
                sequence_id: journal_event_id,
                payload_content_hash: payload_hash,
                normalized_payload_path: None,
                normalized_payload: payload,
                normalized_payload_hash,
                raw_evidence_hashes: Vec::new(),
                freshness_window_ms,
                freshness_deadline_ms: collected_timestamp_ms + freshness_window_ms,
                degradation_state: state.to_string(),
                retention_class: retention_class_for_state(state).to_string(),
                parent_event_ids: if index == 0 {
                    Vec::new()
                } else {
                    vec![journal_event_id - 1]
                },
                metadata: Value::Object(metadata.into_iter().collect()),
            }
        })
        .collect();

    ShadowEvidenceJournalExport {
        schema_version: SHADOW_EVIDENCE_JOURNAL_SCHEMA_VERSION.to_string(),
        rows,
    }
}

fn event_payload(state: &str, index: usize) -> Value {
    match state {
        "degraded" => json!({
            "event_type": "degraded_operation",
            "index": index,
            "operation_id": format!("degraded_op_{index}"),
            "resource_utilization": {
                "cpu_usage": 0.85,
                "memory_usage": 0.90,
                "disk_usage": 0.75
            },
            "latency_metrics": {
                "p50_ms": 250,
                "p95_ms": 1200,
                "p99_ms": 3400
            },
            "status": "degraded",
            "warnings": ["high_resource_usage", "elevated_latency"],
        }),
        "contaminated" => json!({
            "event_type": "contaminated_operation",
            "index": index,
            "operation_id": format!("contaminated_op_{index}"),
            "resource_utilization": {
                "cpu_usage": -0.5,
                "memory_usage": null,
                "disk_usage": "invalid_type"
            },
            "latency_metrics": {
                "p50_ms": 15,
                "p95_ms": 32,
                "p99_ms": 48,
                "invalid_metric": "should_not_exist"
            },
            "status": "contaminated",
            "errors": ["data_corruption", "schema_violation"],
        }),
        "stale" => json!({
            "event_type": "stale_operation",
            "index": index,
            "operation_id": format!("stale_op_{index}"),
            "resource_utilization": {
                "cpu_usage": 0.20,
                "memory_usage": 0.10,
                "disk_usage": 0.03
            },
            "latency_metrics": {
                "p50_ms": 10,
                "p95_ms": 25,
                "p99_ms": 40
            },
            "status": "stale",
            "source_timestamp": "2023-12-31T00:00:00Z",
            "data_age_hours": 24,
        }),
        _ => json!({
            "event_type": "healthy_operation",
            "index": index,
            "operation_id": format!("healthy_op_{index}"),
            "resource_utilization": {
                "cpu_usage": 0.25,
                "memory_usage": 0.15,
                "disk_usage": 0.05
            },
            "latency_metrics": {
                "p50_ms": 12,
                "p95_ms": 28,
                "p99_ms": 45
            },
            "status": "success",
        }),
    }
}

fn retention_class_for_state(state: &str) -> &'static str {
    match state {
        "degraded" => "extended",
        "contaminated" => "quarantine",
        "stale" => "archived",
        _ => "normal",
    }
}

fn expected_decision_hash(payload: &Value) -> String {
    let payload_summary = payload
        .get("operation_id")
        .cloned()
        .unwrap_or_else(|| json!("unknown"));
    let status = payload
        .get("status")
        .cloned()
        .unwrap_or_else(|| json!("unknown"));
    let decision_data = json!({
        "decision_type": "test_decision",
        "payload_summary": payload_summary,
        "status": status,
        "deterministic_seed": "replay_fixture_v1"
    });
    hex_encode(ContentHash::compute(&payload_bytes(&decision_data)).as_bytes())
}

fn payload_bytes(payload: &Value) -> Vec<u8> {
    serde_json::to_vec(payload).expect("fixture payload should serialize")
}

fn corrupt_hex_hash(hash: &str) -> String {
    let mut corrupt = hash.to_string();
    let replacement = if corrupt.starts_with('0') { "1" } else { "0" };
    corrupt.replace_range(0..1, replacement);
    corrupt
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Smoke test that exits non-zero on nondeterminism or missing provenance.
/// This test ensures the replay verification system works as required.
#[test]
fn shadow_replay_smoke_test() {
    println!("🧪 Starting shadow replay verification smoke test...");

    let mut verifier =
        ShadowReplayVerifier::with_default_config().expect("default replay config should be valid");

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
                assert!(
                    !report.replay_recipe.input_checkpoint.is_empty(),
                    "Missing provenance in {} fixture replay recipe",
                    case_name
                );
                assert!(
                    !report.replay_recipe.replay_command.is_empty(),
                    "Missing replay command in {} fixture",
                    case_name
                );
                assert!(
                    !report.replay_recipe.referenced_artifacts.is_empty(),
                    "Missing referenced artifacts in {} fixture",
                    case_name
                );

                // Verify report structure
                assert!(
                    !report.report_id.to_string().is_empty(),
                    "Missing report ID for {} fixture",
                    case_name
                );
                assert!(
                    report.detection_timestamp_ms > 0,
                    "Invalid timestamp for {} fixture",
                    case_name
                );

                // Test determinism by replaying twice
                let expected_schema_version = export.schema_version.clone();
                let second_result =
                    verifier.replay_export(export, format!("smoke_test_{}_repeat", case_name));
                match second_result {
                    Ok(second_report) => {
                        // Verify deterministic behavior
                        assert_eq!(
                            report.detected_drift.len(),
                            second_report.detected_drift.len(),
                            "Non-deterministic drift count in {} fixture",
                            case_name
                        );
                        assert_eq!(
                            report.is_expected_migration, second_report.is_expected_migration,
                            "Non-deterministic migration flag in {} fixture",
                            case_name
                        );
                    }
                    Err(e) => {
                        panic!(
                            "Non-deterministic behavior: {} fixture succeeded first time but failed second time: {}",
                            case_name, e
                        );
                    }
                }

                println!(
                    "    ✓ {} journal: replay successful, {} drift items detected",
                    case_name,
                    report.detected_drift.len()
                );

                // For contaminated fixtures, expect drift detection
                if case_name == "contaminated" {
                    assert!(
                        !report.detected_drift.is_empty(),
                        "Contaminated fixture should detect drift but found none"
                    );
                    assert!(
                        !report.is_expected_migration,
                        "Contaminated fixture should not be considered expected migration"
                    );
                }

                // Verify schema version consistency
                assert_eq!(
                    report.source_export.schema_version, expected_schema_version,
                    "Schema version mismatch in {} fixture",
                    case_name
                );
            }
            Err(e) => {
                // Some fixtures (especially contaminated) may legitimately fail
                if case_name == "contaminated" {
                    expected_failures += 1;
                    println!(
                        "    ✓ {} journal: expected failure detected: {}",
                        case_name, e
                    );
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
    assert!(
        successful_replays > 0,
        "No successful replays - this indicates a systemic issue"
    );

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
    assert_eq!(default_config.replay_timestamp_ms, None);
    assert!(default_config.verify_payload_hashes);
    assert!(default_config.require_deterministic_ordering);

    // Test custom config
    let custom_config = ReplayConfig {
        max_events_per_batch: 500,
        replay_timeout_ms: 15_000,
        replay_timestamp_ms: Some(FIXTURE_BASE_TIMESTAMP_MS as u64),
        allow_schema_migration: false,
        freshness_tolerance_ms: 2000,
        verify_payload_hashes: true,
        require_deterministic_ordering: false,
    };

    let mut verifier = ShadowReplayVerifier::new(custom_config, 600)
        .expect("custom replay config should be valid");
    let report = verifier
        .replay_export(create_healthy_journal_fixture(), "config_test".to_string())
        .expect("custom replay config should replay a healthy fixture");
    assert_eq!(
        report.detection_timestamp_ms,
        FIXTURE_BASE_TIMESTAMP_MS as u64
    );
    assert!(!report.is_expected_migration);

    println!("✅ Replay configuration validation passed!");
}

/// Test that replay recipes contain exact input artifacts and commands.
#[test]
fn test_replay_recipe_completeness() {
    println!("📋 Testing replay recipe completeness...");

    let mut verifier =
        ShadowReplayVerifier::with_default_config().expect("default replay config should be valid");
    let export = create_healthy_journal_fixture();

    let result = verifier
        .replay_export(export, "recipe_test".to_string())
        .unwrap();
    let recipe = &result.replay_recipe;

    // Verify recipe completeness
    assert!(
        !recipe.input_checkpoint.is_empty(),
        "Recipe missing input checkpoint"
    );
    assert!(
        !recipe.replay_command.is_empty(),
        "Recipe missing replay command"
    );
    assert!(
        !recipe.environment_vars.is_empty(),
        "Recipe missing environment variables"
    );
    assert!(
        !recipe.expected_outputs.is_empty(),
        "Recipe missing expected outputs"
    );
    assert!(
        !recipe.referenced_artifacts.is_empty(),
        "Recipe missing referenced artifacts"
    );

    // Verify command structure
    assert!(
        recipe.replay_command.contains(&"cargo".to_string()),
        "Recipe should contain cargo command"
    );
    assert!(
        recipe.replay_command.contains(&"test".to_string()),
        "Recipe should contain test command"
    );
    assert!(
        recipe
            .replay_command
            .contains(&"frankenengine-engine".to_string()),
        "Recipe should target frankenengine-engine package"
    );

    // Verify environment variables include required ones
    assert!(
        recipe.environment_vars.contains_key("RUST_BACKTRACE"),
        "Recipe should include RUST_BACKTRACE"
    );
    assert!(
        recipe.environment_vars.contains_key("TARGET_ENV"),
        "Recipe should include TARGET_ENV"
    );

    // Verify referenced artifacts include core replay components
    let artifacts_str = recipe.referenced_artifacts.join(",");
    assert!(
        artifacts_str.contains("shadow_replay_verifier.rs"),
        "Recipe should reference shadow_replay_verifier.rs"
    );
    assert!(
        artifacts_str.contains("shadow_decision_composer.rs"),
        "Recipe should reference shadow_decision_composer.rs"
    );

    println!("✅ Replay recipe completeness test passed!");
}
