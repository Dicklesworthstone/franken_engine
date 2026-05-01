#![forbid(unsafe_code)]

//! Integration tests for events.jsonl validation to ensure malformed JSON is rejected.

use frankenengine_engine::proof_artifact::{ProofArtifactError, validate_event_json_line};
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn malformed_events_jsonl_is_rejected() {
    let malformed_events = [
        // Missing required fields
        r#"{"schema_version": "franken-engine.proof-artifact-event.v1"}"#,
        // Invalid schema version
        r#"{"schema_version": "invalid", "event_name": "test", "severity": "info", "step_id": "step", "decision": "pass"}"#,
        // Malformed JSON
        r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "unclosed": "#,
        // Empty required fields
        r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "", "severity": "info", "step_id": "", "decision": "pass"}"#,
    ];

    for (i, malformed_json) in malformed_events.iter().enumerate() {
        let result = validate_event_json_line(malformed_json);
        assert!(
            result.is_err(),
            "Malformed JSON {} should be rejected: {}",
            i,
            malformed_json
        );
    }
}

#[test]
fn deeply_nested_json_is_rejected() {
    // Create JSON with nesting depth > 16
    let mut deep_json = String::from(
        r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "test", "severity": "info", "step_id": "step", "decision": "pass", "data": "#,
    );

    // Add 20 levels of nesting
    for _ in 0..20 {
        deep_json.push_str(r#"{"nested": "#);
    }
    deep_json.push_str("\"value\"");
    for _ in 0..20 {
        deep_json.push('}');
    }
    deep_json.push('}');

    let result = validate_event_json_line(&deep_json);
    assert!(result.is_err());

    match result {
        Err(ProofArtifactError::JsonTooDeep { depth, max }) => {
            assert!(depth > max, "Depth {} should exceed max {}", depth, max);
        }
        _ => panic!("Expected JsonTooDeep error"),
    }
}

#[test]
fn oversized_json_line_is_rejected() {
    // Create a JSON line larger than 64KB
    let large_value = "x".repeat(70000); // 70KB
    let oversized_json = format!(
        r#"{{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "test", "severity": "info", "step_id": "step", "decision": "pass", "large_data": "{}"}}"#,
        large_value
    );

    let result = validate_event_json_line(&oversized_json);
    assert!(result.is_err());

    match result {
        Err(ProofArtifactError::JsonTooLarge { size, max }) => {
            assert!(size > max, "Size {} should exceed max {}", size, max);
        }
        _ => panic!("Expected JsonTooLarge error"),
    }
}

#[test]
fn valid_events_jsonl_is_accepted() {
    let valid_events = [
        r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "step.started", "severity": "info", "step_id": "step-001", "decision": "proceed"}"#,
        r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "step.completed", "severity": "info", "step_id": "step-001", "command_id": "cmd-001", "exit_code": 0, "duration_ms": 1000, "decision": "passed"}"#,
        r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "step.failed", "severity": "error", "step_id": "step-002", "decision": "failed", "remediation": "Check logs"}"#,
    ];

    for (i, valid_json) in valid_events.iter().enumerate() {
        let result = validate_event_json_line(valid_json);
        assert!(
            result.is_ok(),
            "Valid JSON {} should be accepted: {}",
            i,
            valid_json
        );
    }
}

#[test]
fn bundle_doctor_detects_malformed_events_in_file() {
    // Create a temporary events.jsonl file with mixed valid/invalid content
    let temp_file = NamedTempFile::new().expect("create temp file");
    let temp_path = temp_file.path();

    let events_content = r#"{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "valid", "severity": "info", "step_id": "step-001", "decision": "pass"}
{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "also-valid", "severity": "info", "step_id": "step-002", "decision": "pass"}
{"schema_version": "invalid-schema", "event_name": "invalid", "severity": "info", "step_id": "step-003", "decision": "pass"}
{"malformed": json without closing brace
{"schema_version": "franken-engine.proof-artifact-event.v1", "event_name": "", "severity": "info", "step_id": "", "decision": "pass"}
"#;

    fs::write(temp_path, events_content).expect("write temp file");

    // The bundle doctor should be able to detect these issues
    // (We can't easily test the shell script here, but we can validate using our Rust functions)

    let lines: Vec<&str> = events_content.lines().collect();
    let mut valid_count = 0;
    let mut invalid_count = 0;

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        match validate_event_json_line(line) {
            Ok(_) => valid_count += 1,
            Err(_) => invalid_count += 1,
        }
    }

    assert_eq!(valid_count, 2, "Should have 2 valid events");
    assert_eq!(invalid_count, 3, "Should have 3 invalid events");
}
