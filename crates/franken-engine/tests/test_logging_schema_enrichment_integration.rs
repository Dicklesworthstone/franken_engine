//! Enrichment integration tests for `test_logging_schema`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;

use frankenengine_engine::test_logging_schema::*;

fn valid_event() -> TestLogEvent {
    TestLogEvent {
        schema_version: TEST_LOG_EVENT_SCHEMA_VERSION.to_string(),
        scenario_id: "scenario-1".to_string(),
        fixture_id: "fixture-1".to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        lane: TestLane::Runtime,
        component: "comp".to_string(),
        event: "evt".to_string(),
        outcome: "pass".to_string(),
        error_code: "none".to_string(),
        seed: 42,
        timing_us: 100,
        timestamp_unix_ms: 1_700_000_000_000,
        failure_taxonomy: None,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!TEST_LOGGING_CONTRACT_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_event_schema_version_non_empty() {
    assert!(!TEST_LOG_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_failure_code_non_empty() {
    assert!(!TEST_LOGGING_FAILURE_CODE.is_empty());
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!TEST_LOGGING_COMPONENT.is_empty());
}

#[test]
fn enrichment_rgc_bead_id_starts_with_bd() {
    assert!(RGC_STRUCTURED_LOGGING_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_rgc_redaction_audit_schema_non_empty() {
    assert!(!RGC_SECRET_REDACTION_AUDIT_SCHEMA_VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// TestLane serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_test_lane_serde_roundtrip() {
    for lane in [
        TestLane::Compiler,
        TestLane::Runtime,
        TestLane::Router,
        TestLane::Governance,
        TestLane::E2e,
    ] {
        let json = serde_json::to_string(&lane).unwrap();
        let back: TestLane = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, back);
    }
}

// ---------------------------------------------------------------------------
// FailureTaxonomy serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_failure_taxonomy_serde_roundtrip() {
    for t in [
        FailureTaxonomy::DeterminismDrift,
        FailureTaxonomy::InvariantViolation,
        FailureTaxonomy::Timeout,
        FailureTaxonomy::ResourceBudget,
        FailureTaxonomy::SchemaDrift,
        FailureTaxonomy::Unknown,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: FailureTaxonomy = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ---------------------------------------------------------------------------
// DataSensitivity / RedactionAction serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_data_sensitivity_serde_roundtrip() {
    for s in [
        DataSensitivity::Public,
        DataSensitivity::Internal,
        DataSensitivity::Sensitive,
        DataSensitivity::Secret,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: DataSensitivity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_redaction_action_serde_roundtrip() {
    for a in [
        RedactionAction::Redact,
        RedactionAction::Hash,
        RedactionAction::Drop,
    ] {
        let json = serde_json::to_string(&a).unwrap();
        let back: RedactionAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

// ---------------------------------------------------------------------------
// TestLoggingSchemaSpec
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_spec_has_required_fields() {
    let spec = TestLoggingSchemaSpec::default();
    assert!(!spec.required_fields.is_empty());
}

#[test]
fn enrichment_default_spec_has_redaction_rules() {
    let spec = TestLoggingSchemaSpec::default();
    assert!(!spec.redaction_rules.is_empty());
}

#[test]
fn enrichment_default_spec_retention_30_days() {
    let spec = TestLoggingSchemaSpec::default();
    assert_eq!(spec.retention_policy.retention_days, 30);
}

#[test]
fn enrichment_default_spec_serde_roundtrip() {
    let spec = TestLoggingSchemaSpec::default();
    let json = serde_json::to_string(&spec).unwrap();
    let back: TestLoggingSchemaSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ---------------------------------------------------------------------------
// validate_event
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_valid_event_no_failures() {
    let event = valid_event();
    let failures = validate_event(&event);
    assert!(failures.is_empty());
}

#[test]
fn enrichment_validate_event_wrong_schema_version() {
    let mut event = valid_event();
    event.schema_version = "wrong".to_string();
    let failures = validate_event(&event);
    assert!(
        failures
            .iter()
            .any(|f| f.error_code == ValidationErrorCode::SchemaVersionMismatch)
    );
}

#[test]
fn enrichment_validate_event_empty_scenario_id() {
    let mut event = valid_event();
    event.scenario_id = "".to_string();
    let failures = validate_event(&event);
    assert!(failures.iter().any(|f| f.message.contains("scenario_id")));
}

#[test]
fn enrichment_validate_event_zero_timing() {
    let mut event = valid_event();
    event.timing_us = 0;
    let failures = validate_event(&event);
    assert!(failures.iter().any(|f| f.message.contains("timing_us")));
}

// ---------------------------------------------------------------------------
// validate_correlation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_correlation_single_event_ok() {
    let event = valid_event();
    let failures = validate_correlation(&[event]);
    assert!(failures.is_empty());
}

#[test]
fn enrichment_validate_correlation_empty_events() {
    let failures = validate_correlation(&[]);
    assert!(!failures.is_empty());
}

#[test]
fn enrichment_validate_correlation_mismatched_trace() {
    let e1 = valid_event();
    let mut e2 = valid_event();
    e2.trace_id = "different-trace".to_string();
    let failures = validate_correlation(&[e1, e2]);
    assert!(failures.iter().any(|f| f.message.contains("trace_id")));
}

// ---------------------------------------------------------------------------
// detect_secret_patterns
// ---------------------------------------------------------------------------

#[test]
fn enrichment_detect_secret_no_secrets() {
    let record = BTreeMap::from([("key".to_string(), "value".to_string())]);
    let matches = detect_secret_patterns(&record);
    assert!(matches.is_empty());
}

#[test]
fn enrichment_detect_secret_password_inline() {
    let record = BTreeMap::from([("data".to_string(), "password=hunter2".to_string())]);
    let matches = detect_secret_patterns(&record);
    assert!(!matches.is_empty());
}

#[test]
fn enrichment_detect_secret_bearer_token() {
    let record = BTreeMap::from([("auth".to_string(), "bearer abc123def456".to_string())]);
    let matches = detect_secret_patterns(&record);
    assert!(!matches.is_empty());
}

#[test]
fn enrichment_detect_redacted_value_not_secret() {
    let record = BTreeMap::from([("field".to_string(), "[REDACTED]".to_string())]);
    let matches = detect_secret_patterns(&record);
    assert!(matches.is_empty());
}

// ---------------------------------------------------------------------------
// apply_redaction / apply_redaction_with_audit
// ---------------------------------------------------------------------------

#[test]
fn enrichment_apply_redaction_replaces_sensitive() {
    let spec = TestLoggingSchemaSpec::default();
    let mut record = BTreeMap::new();
    record.insert(
        "payload.user_email".to_string(),
        "test@example.com".to_string(),
    );
    record.insert("payload.auth_token".to_string(), "secret123".to_string());
    record.insert("payload.ip_address".to_string(), "192.168.1.1".to_string());

    let redacted = apply_redaction(&record, &spec);
    assert!(
        redacted
            .get("payload.user_email")
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(redacted.get("payload.ip_address").unwrap(), "[REDACTED]");
}

#[test]
fn enrichment_apply_redaction_audit_has_entries() {
    let spec = TestLoggingSchemaSpec::default();
    let mut record = BTreeMap::new();
    record.insert(
        "payload.user_email".to_string(),
        "user@test.com".to_string(),
    );
    let report = apply_redaction_with_audit(&record, &spec);
    assert!(!report.audit_entries.is_empty());
    assert!(!report.report_hash.is_empty());
}

#[test]
fn enrichment_apply_redaction_audit_outcome_pass() {
    let spec = TestLoggingSchemaSpec::default();
    let record = BTreeMap::new();
    let report = apply_redaction_with_audit(&record, &spec);
    assert_eq!(report.outcome, "pass");
}

// ---------------------------------------------------------------------------
// validate_redaction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_redaction_clean_record() {
    let spec = TestLoggingSchemaSpec::default();
    let record = BTreeMap::new();
    let failures = validate_redaction(&record, &spec);
    assert!(failures.is_empty());
}

#[test]
fn enrichment_validate_redaction_unredacted_field() {
    let spec = TestLoggingSchemaSpec::default();
    let mut record = BTreeMap::new();
    record.insert("payload.ip_address".to_string(), "192.168.1.1".to_string());
    let failures = validate_redaction(&record, &spec);
    assert!(!failures.is_empty());
}

// ---------------------------------------------------------------------------
// validate_events
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_events_valid() {
    let events = vec![valid_event(), valid_event()];
    let report = validate_events(&events);
    assert!(report.valid);
    assert_eq!(report.outcome, "pass");
}

#[test]
fn enrichment_validate_events_empty() {
    let report = validate_events(&[]);
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
}

// ---------------------------------------------------------------------------
// rgc_structured_logging_spec
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rgc_spec_schema_version() {
    let spec = rgc_structured_logging_spec();
    assert_eq!(
        spec.schema_version,
        RGC_STRUCTURED_LOGGING_CONTRACT_SCHEMA_VERSION
    );
}

// ---------------------------------------------------------------------------
// validate_logging_contract
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_logging_contract_default_valid() {
    let spec = TestLoggingSchemaSpec::default();
    let failures = validate_logging_contract(&spec);
    assert!(failures.is_empty());
}

#[test]
fn enrichment_validate_logging_contract_empty_schema_version() {
    let mut spec = TestLoggingSchemaSpec::default();
    spec.schema_version = "".to_string();
    let failures = validate_logging_contract(&spec);
    assert!(!failures.is_empty());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validation_report_serde_roundtrip() {
    let report = validate_events(&[valid_event()]);
    let json = serde_json::to_string(&report).unwrap();
    let back: ValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.valid, back.valid);
}

#[test]
fn enrichment_redaction_audit_report_serialize_deserialize() {
    let spec = TestLoggingSchemaSpec::default();
    let record = BTreeMap::new();
    let report = apply_redaction_with_audit(&record, &spec);
    let json = serialize_redaction_audit_report(&report).unwrap();
    let back = deserialize_redaction_audit_report(&json).unwrap();
    assert_eq!(report.report_hash, back.report_hash);
}

#[test]
fn enrichment_correlation_key_deterministic() {
    let e = valid_event();
    let k1 = e.correlation_key();
    let k2 = e.correlation_key();
    assert_eq!(k1, k2);
}
