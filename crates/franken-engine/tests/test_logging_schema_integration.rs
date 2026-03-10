#![forbid(unsafe_code)]

//! Integration tests for `frankenengine_engine::test_logging_schema`.
//! Exercises the public API from outside the crate boundary.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::test_logging_schema::{
    DataSensitivity, FailureTaxonomy, RGC_SECRET_REDACTION_AUDIT_BEAD_ID,
    RGC_SECRET_REDACTION_AUDIT_COMPONENT, RGC_SECRET_REDACTION_AUDIT_EVENT,
    RGC_SECRET_REDACTION_AUDIT_SCHEMA_VERSION, RGC_STRUCTURED_LOGGING_BEAD_ID,
    RGC_STRUCTURED_LOGGING_COMPONENT, RGC_STRUCTURED_LOGGING_CONTRACT_SCHEMA_VERSION,
    RGC_STRUCTURED_LOGGING_FAILURE_CODE, RedactionAction, RedactionRule, RetentionPolicy,
    TEST_LOG_EVENT_SCHEMA_VERSION, TEST_LOGGING_COMPONENT, TEST_LOGGING_CONTRACT_SCHEMA_VERSION,
    TEST_LOGGING_FAILURE_CODE, TestLane, TestLogEvent, TestLoggingSchemaSpec, ValidationErrorCode,
    ValidationFailure, ValidationReport, apply_redaction, apply_redaction_with_audit,
    deserialize_redaction_audit_report, detect_secret_patterns, rgc_structured_logging_spec,
    serialize_redaction_audit_report, validate_correlation, validate_event, validate_events,
    validate_logging_contract, validate_redaction, validate_schema_evolution,
};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn baseline_event() -> TestLogEvent {
    TestLogEvent {
        schema_version: TEST_LOG_EVENT_SCHEMA_VERSION.to_string(),
        scenario_id: "scenario-int-1".to_string(),
        fixture_id: "fixture-int-1".to_string(),
        trace_id: "trace-int-1".to_string(),
        decision_id: "decision-int-1".to_string(),
        policy_id: "policy-int-1".to_string(),
        lane: TestLane::Runtime,
        component: "integration_kernel".to_string(),
        event: "integration_test_completed".to_string(),
        outcome: "pass".to_string(),
        error_code: "none".to_string(),
        seed: 12345,
        timing_us: 200,
        timestamp_unix_ms: 1_740_000_000_000,
        failure_taxonomy: None,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = read_to_string(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct RgcLoggingContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    logging_schema: RgcLoggingSchema,
    correlation_policy: RgcCorrelationPolicy,
    failure_policy: RgcFailurePolicy,
    redaction_audit_contract: RgcRedactionAuditContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RgcLoggingSchema {
    event_schema_version: String,
    required_fields: Vec<String>,
    required_correlation_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RgcCorrelationPolicy {
    correlation_key_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RgcFailurePolicy {
    mode: String,
    error_code: String,
}

#[derive(Debug, Deserialize)]
struct RgcRedactionAuditContract {
    bead_id: String,
    schema_version: String,
    component: String,
    event: String,
    deterministic_serialization: RgcDeterministicSerialization,
}

#[derive(Debug, Deserialize)]
struct RgcDeterministicSerialization {
    serialize_fn: String,
    deserialize_fn: String,
    hash_field: String,
}

// ===================================================================
// 1. Public constants
// ===================================================================

#[test]
fn constants_are_nonempty() {
    assert!(!TEST_LOGGING_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!TEST_LOG_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!TEST_LOGGING_FAILURE_CODE.is_empty());
    assert!(!TEST_LOGGING_COMPONENT.is_empty());
}

#[test]
fn contract_schema_version_contains_version_marker() {
    assert!(
        TEST_LOGGING_CONTRACT_SCHEMA_VERSION.contains("v1"),
        "expected v1 in contract schema version"
    );
}

#[test]
fn event_schema_version_contains_version_marker() {
    assert!(
        TEST_LOG_EVENT_SCHEMA_VERSION.contains("v1"),
        "expected v1 in event schema version"
    );
}

#[test]
fn failure_code_has_frx_prefix() {
    assert!(
        TEST_LOGGING_FAILURE_CODE.starts_with("FE-FRX"),
        "failure code should start with FE-FRX"
    );
}

// ===================================================================
// 2. TestLane enum
// ===================================================================

#[test]
fn test_lane_serde_roundtrip_all_variants() {
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

#[test]
fn test_lane_serde_snake_case() {
    assert_eq!(serde_json::to_string(&TestLane::E2e).unwrap(), "\"e2e\"");
    assert_eq!(
        serde_json::to_string(&TestLane::Compiler).unwrap(),
        "\"compiler\""
    );
    assert_eq!(
        serde_json::to_string(&TestLane::Governance).unwrap(),
        "\"governance\""
    );
}

#[test]
fn test_lane_ordering() {
    let mut lanes = vec![
        TestLane::E2e,
        TestLane::Compiler,
        TestLane::Governance,
        TestLane::Runtime,
        TestLane::Router,
    ];
    lanes.sort();
    assert_eq!(
        lanes,
        vec![
            TestLane::Compiler,
            TestLane::Runtime,
            TestLane::Router,
            TestLane::Governance,
            TestLane::E2e,
        ]
    );
}

#[test]
fn test_lane_clone_eq() {
    let lane = TestLane::Router;
    let cloned = lane;
    assert_eq!(lane, cloned);
}

// ===================================================================
// 3. FailureTaxonomy enum
// ===================================================================

#[test]
fn failure_taxonomy_serde_roundtrip_all_variants() {
    for tax in [
        FailureTaxonomy::DeterminismDrift,
        FailureTaxonomy::InvariantViolation,
        FailureTaxonomy::Timeout,
        FailureTaxonomy::ResourceBudget,
        FailureTaxonomy::SchemaDrift,
        FailureTaxonomy::Unknown,
    ] {
        let json = serde_json::to_string(&tax).unwrap();
        let back: FailureTaxonomy = serde_json::from_str(&json).unwrap();
        assert_eq!(tax, back);
    }
}

#[test]
fn failure_taxonomy_snake_case_names() {
    assert_eq!(
        serde_json::to_string(&FailureTaxonomy::DeterminismDrift).unwrap(),
        "\"determinism_drift\""
    );
    assert_eq!(
        serde_json::to_string(&FailureTaxonomy::ResourceBudget).unwrap(),
        "\"resource_budget\""
    );
}

// ===================================================================
// 4. DataSensitivity enum
// ===================================================================

#[test]
fn data_sensitivity_serde_roundtrip_all_variants() {
    for sens in [
        DataSensitivity::Public,
        DataSensitivity::Internal,
        DataSensitivity::Sensitive,
        DataSensitivity::Secret,
    ] {
        let json = serde_json::to_string(&sens).unwrap();
        let back: DataSensitivity = serde_json::from_str(&json).unwrap();
        assert_eq!(sens, back);
    }
}

// ===================================================================
// 5. RedactionAction enum
// ===================================================================

#[test]
fn redaction_action_serde_roundtrip_all_variants() {
    for act in [
        RedactionAction::Redact,
        RedactionAction::Hash,
        RedactionAction::Drop,
    ] {
        let json = serde_json::to_string(&act).unwrap();
        let back: RedactionAction = serde_json::from_str(&json).unwrap();
        assert_eq!(act, back);
    }
}

// ===================================================================
// 6. ValidationErrorCode enum
// ===================================================================

#[test]
fn validation_error_code_serde_roundtrip_all_variants() {
    for code in [
        ValidationErrorCode::MissingRequiredField,
        ValidationErrorCode::SchemaVersionMismatch,
        ValidationErrorCode::CorrelationMismatch,
        ValidationErrorCode::RedactionPolicyViolation,
        ValidationErrorCode::SecretPatternLeak,
        ValidationErrorCode::ContractValidationViolation,
    ] {
        let json = serde_json::to_string(&code).unwrap();
        let back: ValidationErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

// ===================================================================
// 7. RedactionRule struct
// ===================================================================

#[test]
fn redaction_rule_construction_and_field_access() {
    let rule = RedactionRule {
        field_path: "payload.token".to_string(),
        sensitivity: DataSensitivity::Secret,
        action: RedactionAction::Drop,
        rationale: "must never be retained".to_string(),
    };
    assert_eq!(rule.field_path, "payload.token");
    assert_eq!(rule.sensitivity, DataSensitivity::Secret);
    assert_eq!(rule.action, RedactionAction::Drop);
    assert_eq!(rule.rationale, "must never be retained");
}

#[test]
fn redaction_rule_serde_roundtrip() {
    let rule = RedactionRule {
        field_path: "payload.pii".to_string(),
        sensitivity: DataSensitivity::Sensitive,
        action: RedactionAction::Redact,
        rationale: "anonymize PII".to_string(),
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: RedactionRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// ===================================================================
// 8. RetentionPolicy struct
// ===================================================================

#[test]
fn retention_policy_construction_and_field_access() {
    let pol = RetentionPolicy {
        retention_days: 90,
        require_redaction_for_sensitive: true,
        permit_raw_seed_storage: false,
    };
    assert_eq!(pol.retention_days, 90);
    assert!(pol.require_redaction_for_sensitive);
    assert!(!pol.permit_raw_seed_storage);
}

#[test]
fn retention_policy_serde_roundtrip() {
    let pol = RetentionPolicy {
        retention_days: 365,
        require_redaction_for_sensitive: false,
        permit_raw_seed_storage: true,
    };
    let json = serde_json::to_string(&pol).unwrap();
    let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(pol, back);
}

#[test]
fn retention_policy_zero_days_roundtrip() {
    let pol = RetentionPolicy {
        retention_days: 0,
        require_redaction_for_sensitive: false,
        permit_raw_seed_storage: false,
    };
    let json = serde_json::to_string(&pol).unwrap();
    let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back.retention_days, 0);
}

// ===================================================================
// 9. TestLoggingSchemaSpec (Default, fields, serde)
// ===================================================================

#[test]
fn default_spec_schema_versions() {
    let spec = TestLoggingSchemaSpec::default();
    assert_eq!(spec.schema_version, TEST_LOGGING_CONTRACT_SCHEMA_VERSION);
    assert_eq!(spec.event_schema_version, TEST_LOG_EVENT_SCHEMA_VERSION);
}

#[test]
fn default_spec_required_fields_count() {
    let spec = TestLoggingSchemaSpec::default();
    assert_eq!(spec.required_fields.len(), 13);
}

#[test]
fn default_spec_required_correlation_ids_count() {
    let spec = TestLoggingSchemaSpec::default();
    assert_eq!(spec.required_correlation_ids.len(), 5);
}

#[test]
fn default_spec_correlation_ids_subset_of_required_fields() {
    let spec = TestLoggingSchemaSpec::default();
    for id in &spec.required_correlation_ids {
        assert!(
            spec.required_fields.contains(id),
            "correlation id `{id}` must be in required_fields"
        );
    }
}

#[test]
fn default_spec_retention_policy_values() {
    let spec = TestLoggingSchemaSpec::default();
    assert_eq!(spec.retention_policy.retention_days, 30);
    assert!(spec.retention_policy.require_redaction_for_sensitive);
    assert!(!spec.retention_policy.permit_raw_seed_storage);
}

#[test]
fn default_spec_has_three_redaction_rules() {
    let spec = TestLoggingSchemaSpec::default();
    assert_eq!(spec.redaction_rules.len(), 3);
}

#[test]
fn default_spec_deterministic() {
    let a = TestLoggingSchemaSpec::default();
    let b = TestLoggingSchemaSpec::default();
    assert_eq!(a, b);
}

#[test]
fn default_spec_serde_roundtrip() {
    let spec = TestLoggingSchemaSpec::default();
    let json = serde_json::to_string(&spec).unwrap();
    let back: TestLoggingSchemaSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ===================================================================
// 10. TestLogEvent (construction, correlation_key, serde)
// ===================================================================

#[test]
fn test_log_event_serde_roundtrip() {
    let event = baseline_event();
    let json = serde_json::to_string(&event).unwrap();
    let back: TestLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn test_log_event_with_failure_taxonomy_serde() {
    let mut event = baseline_event();
    event.failure_taxonomy = Some(FailureTaxonomy::Timeout);
    let json = serde_json::to_string(&event).unwrap();
    let back: TestLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.failure_taxonomy, Some(FailureTaxonomy::Timeout));
}

#[test]
fn test_log_event_none_taxonomy_serde() {
    let event = baseline_event();
    let json = serde_json::to_string(&event).unwrap();
    let back: TestLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.failure_taxonomy, None);
}

#[test]
fn correlation_key_deterministic() {
    let a = baseline_event();
    let b = baseline_event();
    assert_eq!(a.correlation_key(), b.correlation_key());
}

#[test]
fn correlation_key_contains_all_five_fields() {
    let event = baseline_event();
    let key = event.correlation_key();
    assert!(key.contains(&event.scenario_id));
    assert!(key.contains(&event.trace_id));
    assert!(key.contains(&event.decision_id));
    assert!(key.contains(&event.policy_id));
    assert!(key.contains(&event.seed.to_string()));
    assert_eq!(key.matches('|').count(), 4);
}

#[test]
fn correlation_key_differs_by_scenario() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.scenario_id = "scenario-int-other".to_string();
    assert_ne!(a.correlation_key(), b.correlation_key());
}

#[test]
fn correlation_key_differs_by_seed() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.seed = 99999;
    assert_ne!(a.correlation_key(), b.correlation_key());
}

#[test]
fn correlation_key_differs_by_trace_id() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.trace_id = "trace-different".to_string();
    assert_ne!(a.correlation_key(), b.correlation_key());
}

#[test]
fn correlation_key_differs_by_decision_id() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.decision_id = "decision-different".to_string();
    assert_ne!(a.correlation_key(), b.correlation_key());
}

#[test]
fn correlation_key_differs_by_policy_id() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.policy_id = "policy-different".to_string();
    assert_ne!(a.correlation_key(), b.correlation_key());
}

// ===================================================================
// 11. ValidationFailure and ValidationReport (serde)
// ===================================================================

#[test]
fn validation_failure_serde_roundtrip() {
    let failure = ValidationFailure {
        component: TEST_LOGGING_COMPONENT.to_string(),
        event: "test_event".to_string(),
        outcome: "fail".to_string(),
        error_code: ValidationErrorCode::MissingRequiredField,
        message: "field X missing".to_string(),
    };
    let json = serde_json::to_string(&failure).unwrap();
    let back: ValidationFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(failure, back);
}

#[test]
fn validation_report_serde_roundtrip() {
    let report = validate_events(&[baseline_event()]);
    let json = serde_json::to_string(&report).unwrap();
    let back: ValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn validation_report_clone_eq() {
    let report = validate_events(&[baseline_event()]);
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

// ===================================================================
// 12. validate_event
// ===================================================================

#[test]
fn validate_event_passes_on_valid_event() {
    let failures = validate_event(&baseline_event());
    assert!(failures.is_empty());
}

#[test]
fn validate_event_detects_schema_version_mismatch() {
    let mut event = baseline_event();
    event.schema_version = "wrong-version".to_string();
    let failures = validate_event(&event);
    assert!(
        failures
            .iter()
            .any(|f| f.error_code == ValidationErrorCode::SchemaVersionMismatch)
    );
}

#[test]
fn validate_event_detects_empty_scenario_id() {
    let mut event = baseline_event();
    event.scenario_id.clear();
    let failures = validate_event(&event);
    assert!(failures.iter().any(|f| f.message.contains("scenario_id")));
}

#[test]
fn validate_event_detects_whitespace_only_component() {
    let mut event = baseline_event();
    event.component = "   ".to_string();
    let failures = validate_event(&event);
    assert!(failures.iter().any(|f| f.message.contains("component")));
}

#[test]
fn validate_event_detects_zero_timing() {
    let mut event = baseline_event();
    event.timing_us = 0;
    let failures = validate_event(&event);
    assert!(failures.iter().any(|f| f.message.contains("timing_us")));
}

#[test]
fn validate_event_detects_zero_timestamp() {
    let mut event = baseline_event();
    event.timestamp_unix_ms = 0;
    let failures = validate_event(&event);
    assert!(
        failures
            .iter()
            .any(|f| f.message.contains("timestamp_unix_ms"))
    );
}

#[test]
fn validate_event_multiple_missing_fields() {
    let mut event = baseline_event();
    event.scenario_id.clear();
    event.trace_id.clear();
    event.decision_id.clear();
    event.policy_id.clear();
    event.timing_us = 0;
    event.timestamp_unix_ms = 0;
    let failures = validate_event(&event);
    assert!(failures.len() >= 6);
}

#[test]
fn validate_event_accepts_max_u64_values() {
    let mut event = baseline_event();
    event.seed = u64::MAX;
    event.timing_us = u64::MAX;
    event.timestamp_unix_ms = u64::MAX;
    let failures = validate_event(&event);
    assert!(failures.is_empty());
}

#[test]
fn validate_event_passes_for_each_lane() {
    for lane in [
        TestLane::Compiler,
        TestLane::Runtime,
        TestLane::Router,
        TestLane::Governance,
        TestLane::E2e,
    ] {
        let mut event = baseline_event();
        event.lane = lane;
        assert!(
            validate_event(&event).is_empty(),
            "lane {lane:?} should pass"
        );
    }
}

#[test]
fn validate_event_passes_with_each_failure_taxonomy() {
    for tax in [
        Some(FailureTaxonomy::DeterminismDrift),
        Some(FailureTaxonomy::InvariantViolation),
        Some(FailureTaxonomy::Timeout),
        Some(FailureTaxonomy::ResourceBudget),
        Some(FailureTaxonomy::SchemaDrift),
        Some(FailureTaxonomy::Unknown),
        None,
    ] {
        let mut event = baseline_event();
        event.failure_taxonomy = tax;
        assert!(
            validate_event(&event).is_empty(),
            "taxonomy {tax:?} should pass"
        );
    }
}

// ===================================================================
// 13. validate_correlation
// ===================================================================

#[test]
fn validate_correlation_empty_events() {
    let failures = validate_correlation(&[]);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].message.contains("events"));
}

#[test]
fn validate_correlation_single_event_passes() {
    let failures = validate_correlation(&[baseline_event()]);
    assert!(failures.is_empty());
}

#[test]
fn validate_correlation_matching_events_pass() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.lane = TestLane::Compiler; // different lane, same correlation
    b.event = "compiler_check".to_string();
    let failures = validate_correlation(&[a, b]);
    assert!(failures.is_empty());
}

#[test]
fn validate_correlation_detects_trace_id_mismatch() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.trace_id = "trace-mismatch".to_string();
    let failures = validate_correlation(&[a, b]);
    assert!(failures.iter().any(|f| f.message.contains("trace_id")));
}

#[test]
fn validate_correlation_detects_scenario_id_mismatch() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.scenario_id = "scenario-other".to_string();
    let failures = validate_correlation(&[a, b]);
    assert!(failures.iter().any(|f| f.message.contains("scenario_id")));
}

#[test]
fn validate_correlation_detects_decision_id_mismatch() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.decision_id = "decision-other".to_string();
    let failures = validate_correlation(&[a, b]);
    assert!(failures.iter().any(|f| f.message.contains("decision_id")));
}

#[test]
fn validate_correlation_detects_policy_id_mismatch() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.policy_id = "policy-other".to_string();
    let failures = validate_correlation(&[a, b]);
    assert!(failures.iter().any(|f| f.message.contains("policy_id")));
}

#[test]
fn validate_correlation_detects_seed_mismatch() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.seed = 99999;
    let failures = validate_correlation(&[a, b]);
    assert!(failures.iter().any(|f| f.message.contains("seed")));
}

#[test]
fn validate_correlation_three_events_multiple_mismatches() {
    let a = baseline_event();
    let mut b = baseline_event();
    b.trace_id = "trace-b".to_string();
    let mut c = baseline_event();
    c.policy_id = "policy-c".to_string();
    let failures = validate_correlation(&[a, b, c]);
    assert!(failures.iter().any(|f| f.message.contains("trace_id")));
    assert!(failures.iter().any(|f| f.message.contains("policy_id")));
    assert!(failures.len() >= 2);
}

// ===================================================================
// 14. apply_redaction
// ===================================================================

#[test]
fn apply_redaction_enforces_all_actions() {
    let mut record = BTreeMap::new();
    record.insert(
        "payload.user_email".to_string(),
        "alice@example.com".to_string(),
    );
    record.insert("payload.auth_token".to_string(), "secret-tok".to_string());
    record.insert("payload.ip_address".to_string(), "10.0.0.1".to_string());

    let spec = TestLoggingSchemaSpec::default();
    let redacted = apply_redaction(&record, &spec);

    // Hash action
    let email = redacted.get("payload.user_email").unwrap();
    assert!(email.starts_with("sha256:"));

    // Drop action -> empty string
    assert_eq!(
        redacted.get("payload.auth_token").map(String::as_str),
        Some("")
    );

    // Redact action
    assert_eq!(
        redacted.get("payload.ip_address").map(String::as_str),
        Some("[REDACTED]")
    );
}

#[test]
fn apply_redaction_no_matching_fields_leaves_record_intact() {
    let record = BTreeMap::from([("unrelated".to_string(), "value".to_string())]);
    let spec = TestLoggingSchemaSpec::default();
    let redacted = apply_redaction(&record, &spec);
    assert_eq!(redacted.get("unrelated").map(String::as_str), Some("value"));
    assert_eq!(redacted.len(), 1);
}

#[test]
fn apply_redaction_hash_is_deterministic() {
    let mut record = BTreeMap::new();
    record.insert(
        "payload.user_email".to_string(),
        "bob@example.com".to_string(),
    );
    let spec = TestLoggingSchemaSpec::default();
    let r1 = apply_redaction(&record, &spec);
    let r2 = apply_redaction(&record, &spec);
    assert_eq!(r1, r2);
}

#[test]
fn apply_redaction_different_inputs_yield_different_hashes() {
    let spec = TestLoggingSchemaSpec::default();

    let mut rec_a = BTreeMap::new();
    rec_a.insert(
        "payload.user_email".to_string(),
        "alice@example.com".to_string(),
    );
    let red_a = apply_redaction(&rec_a, &spec);

    let mut rec_b = BTreeMap::new();
    rec_b.insert(
        "payload.user_email".to_string(),
        "bob@example.com".to_string(),
    );
    let red_b = apply_redaction(&rec_b, &spec);

    assert_ne!(
        red_a.get("payload.user_email"),
        red_b.get("payload.user_email")
    );
}

#[test]
fn apply_redaction_preserves_extra_fields() {
    let mut record = BTreeMap::new();
    record.insert("payload.user_email".to_string(), "x@y.com".to_string());
    record.insert("extra_field".to_string(), "keep_me".to_string());

    let spec = TestLoggingSchemaSpec::default();
    let redacted = apply_redaction(&record, &spec);

    assert_eq!(
        redacted.get("extra_field").map(String::as_str),
        Some("keep_me")
    );
    assert!(
        redacted
            .get("payload.user_email")
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn apply_redaction_with_audit_is_deterministic() {
    let record = BTreeMap::from([
        (
            "payload.user_email".to_string(),
            "ops@example.com".to_string(),
        ),
        (
            "payload.auth_token".to_string(),
            "ghp_abcdefghijklmnopqrstuvwxyz123456".to_string(),
        ),
        ("payload.ip_address".to_string(), "10.0.0.4".to_string()),
    ]);

    let mut spec_reordered = TestLoggingSchemaSpec::default();
    spec_reordered.redaction_rules.reverse();
    let spec_default = TestLoggingSchemaSpec::default();

    let report_a = apply_redaction_with_audit(&record, &spec_default);
    let report_b = apply_redaction_with_audit(&record, &spec_reordered);

    assert_eq!(report_a.redacted_record, report_b.redacted_record);
    assert_eq!(report_a.audit_entries, report_b.audit_entries);
    assert_eq!(report_a.report_hash, report_b.report_hash);
    assert!(report_a.report_hash.starts_with("sha256:"));
}

#[test]
fn serialize_redaction_audit_report_is_deterministic() {
    let record = BTreeMap::from([
        (
            "payload.user_email".to_string(),
            "ops@example.com".to_string(),
        ),
        (
            "payload.auth_token".to_string(),
            "ghp_abcdefghijklmnopqrstuvwxyz123456".to_string(),
        ),
        ("payload.ip_address".to_string(), "10.0.0.4".to_string()),
    ]);

    let mut spec_reordered = TestLoggingSchemaSpec::default();
    spec_reordered.redaction_rules.reverse();
    let spec_default = TestLoggingSchemaSpec::default();

    let report_a = apply_redaction_with_audit(&record, &spec_default);
    let report_b = apply_redaction_with_audit(&record, &spec_reordered);

    let serialized_a =
        serialize_redaction_audit_report(&report_a).expect("report_a should serialize");
    let serialized_b =
        serialize_redaction_audit_report(&report_b).expect("report_b should serialize");

    assert_eq!(serialized_a, serialized_b);
}

#[test]
fn serialize_redaction_audit_report_roundtrip_is_lossless() {
    let record = BTreeMap::from([
        (
            "payload.user_email".to_string(),
            "roundtrip@example.com".to_string(),
        ),
        (
            "payload.auth_token".to_string(),
            "secret-inline".to_string(),
        ),
        ("payload.ip_address".to_string(), "192.0.2.10".to_string()),
    ]);
    let spec = TestLoggingSchemaSpec::default();

    let report = apply_redaction_with_audit(&record, &spec);
    let serialized = serialize_redaction_audit_report(&report).expect("report should serialize");
    let decoded =
        deserialize_redaction_audit_report(&serialized).expect("report should deserialize");

    assert_eq!(decoded, report);
}

#[test]
fn detect_secret_patterns_catches_multiple_shapes() {
    let record = BTreeMap::from([
        (
            "payload.aws".to_string(),
            "AKIA1234567890ABCDEF".to_string(),
        ),
        ("payload.inline".to_string(), "password=hunter2".to_string()),
        (
            "payload.slack".to_string(),
            "xoxb-1234-5678-unsafe".to_string(),
        ),
    ]);

    let matches = detect_secret_patterns(&record);
    assert!(
        matches
            .iter()
            .any(|entry| entry.pattern_id == "aws_access_key_id")
    );
    assert!(
        matches
            .iter()
            .any(|entry| entry.pattern_id == "password_inline")
    );
    assert!(
        matches
            .iter()
            .any(|entry| entry.pattern_id == "slack_token")
    );
}

// ===================================================================
// 15. validate_redaction
// ===================================================================

#[test]
fn validate_redaction_passes_on_properly_redacted_record() {
    let record = BTreeMap::from([
        (
            "payload.user_email".to_string(),
            "sha256:abc123def456".to_string(),
        ),
        ("payload.auth_token".to_string(), String::new()),
        ("payload.ip_address".to_string(), "[REDACTED]".to_string()),
    ]);
    let spec = TestLoggingSchemaSpec::default();
    assert!(validate_redaction(&record, &spec).is_empty());
}

#[test]
fn validate_redaction_detects_all_unredacted_fields() {
    let record = BTreeMap::from([
        (
            "payload.user_email".to_string(),
            "raw@email.com".to_string(),
        ),
        ("payload.auth_token".to_string(), "still-secret".to_string()),
        ("payload.ip_address".to_string(), "192.168.1.1".to_string()),
    ]);
    let spec = TestLoggingSchemaSpec::default();
    let failures = validate_redaction(&record, &spec);
    assert_eq!(failures.len(), 3);
    for f in &failures {
        assert_eq!(f.error_code, ValidationErrorCode::RedactionPolicyViolation);
    }
}

#[test]
fn validate_redaction_absent_fields_not_violations() {
    let record = BTreeMap::new();
    let spec = TestLoggingSchemaSpec::default();
    assert!(validate_redaction(&record, &spec).is_empty());
}

#[test]
fn validate_redaction_detects_secret_pattern_leaks() {
    let record = BTreeMap::from([(
        "payload.unruled".to_string(),
        "bearer leaked-token".to_string(),
    )]);
    let spec = TestLoggingSchemaSpec::default();
    let failures = validate_redaction(&record, &spec);
    assert!(
        failures
            .iter()
            .any(|f| f.error_code == ValidationErrorCode::SecretPatternLeak)
    );
}

#[test]
fn apply_then_validate_redaction_roundtrip() {
    let mut record = BTreeMap::new();
    record.insert(
        "payload.user_email".to_string(),
        "carol@example.com".to_string(),
    );
    record.insert("payload.auth_token".to_string(), "my-secret".to_string());
    record.insert("payload.ip_address".to_string(), "172.16.0.1".to_string());

    let spec = TestLoggingSchemaSpec::default();
    let redacted = apply_redaction(&record, &spec);
    let failures = validate_redaction(&redacted, &spec);
    assert!(
        failures.is_empty(),
        "apply_redaction output should pass validate_redaction"
    );
}

// ===================================================================
// 16. validate_events (full lifecycle)
// ===================================================================

#[test]
fn validate_events_valid_batch_passes() {
    let events = vec![baseline_event(), baseline_event()];
    let report = validate_events(&events);
    assert!(report.valid);
    assert_eq!(report.outcome, "pass");
    assert_eq!(report.error_code, "none");
    assert!(report.failures.is_empty());
}

#[test]
fn validate_events_empty_batch_fails() {
    let report = validate_events(&[]);
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
    assert_eq!(report.error_code, TEST_LOGGING_FAILURE_CODE);
    assert_eq!(report.trace_id, "trace-missing");
    assert_eq!(report.decision_id, "decision-missing");
    assert_eq!(report.policy_id, "policy-missing");
}

#[test]
fn validate_events_report_uses_first_event_ids() {
    let event = baseline_event();
    let report = validate_events(std::slice::from_ref(&event));
    assert_eq!(report.trace_id, event.trace_id);
    assert_eq!(report.decision_id, event.decision_id);
    assert_eq!(report.policy_id, event.policy_id);
}

#[test]
fn validate_events_aggregates_event_and_correlation_failures() {
    let mut bad_event = baseline_event();
    bad_event.fixture_id.clear(); // missing field
    let mut mismatched = baseline_event();
    mismatched.trace_id = "trace-other".to_string(); // correlation mismatch

    let report = validate_events(&[bad_event, mismatched]);
    assert!(!report.valid);
    assert!(report.failures.len() >= 2);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.message.contains("fixture_id"))
    );
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.message.contains("trace_id"))
    );
}

#[test]
fn validate_events_report_component_is_logging_component() {
    let report = validate_events(&[baseline_event()]);
    assert_eq!(report.component, TEST_LOGGING_COMPONENT);
}

#[test]
fn validate_events_report_event_field() {
    let report = validate_events(&[baseline_event()]);
    assert_eq!(report.event, "validate_events");
}

#[test]
fn validate_events_report_schema_version() {
    let report = validate_events(&[baseline_event()]);
    assert_eq!(report.schema_version, "frx.test-log-validation-report.v1");
}

// ===================================================================
// 17. Custom spec with custom redaction rules
// ===================================================================

#[test]
fn custom_spec_custom_redaction_rules() {
    let spec = TestLoggingSchemaSpec {
        redaction_rules: vec![RedactionRule {
            field_path: "payload.custom_secret".to_string(),
            sensitivity: DataSensitivity::Secret,
            action: RedactionAction::Drop,
            rationale: "custom rule".to_string(),
        }],
        ..TestLoggingSchemaSpec::default()
    };

    let mut record = BTreeMap::new();
    record.insert("payload.custom_secret".to_string(), "visible".to_string());
    let redacted = apply_redaction(&record, &spec);
    assert_eq!(
        redacted.get("payload.custom_secret").map(String::as_str),
        Some("")
    );
    assert!(validate_redaction(&redacted, &spec).is_empty());
}

#[test]
fn custom_spec_empty_redaction_rules_no_redaction() {
    let spec = TestLoggingSchemaSpec {
        redaction_rules: vec![],
        ..TestLoggingSchemaSpec::default()
    };
    let mut record = BTreeMap::new();
    record.insert(
        "payload.user_email".to_string(),
        "raw@example.com".to_string(),
    );
    let redacted = apply_redaction(&record, &spec);
    assert_eq!(
        redacted.get("payload.user_email").map(String::as_str),
        Some("raw@example.com")
    );
    assert!(validate_redaction(&redacted, &spec).is_empty());
}

// ===================================================================
// 18. RGC-054A contract + evolution checks
// ===================================================================

#[test]
fn rgc_054a_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_STRUCTURED_LOGGING_CONTRACT.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Structured Logging Contract v1",
        "## Scope",
        "## Required Event Fields",
        "## Correlation Keys",
        "## Validation Hooks",
        "## Secret Redaction Audit Contract (RGC-065A)",
        "## Backward-Compatible Evolution Rules",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }

    for phrase in [
        "trace_id",
        "decision_id",
        "policy_id",
        "schema",
        "compatibility",
        "fail-closed",
        "redaction-audit-report",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn rgc_054a_contract_is_machine_readable_and_matches_spec() {
    let path = repo_root().join("docs/rgc_structured_logging_contract_v1.json");
    let contract: RgcLoggingContract = load_json(&path);
    let spec = rgc_structured_logging_spec();

    assert_eq!(
        contract.schema_version,
        RGC_STRUCTURED_LOGGING_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.bead_id, RGC_STRUCTURED_LOGGING_BEAD_ID);
    assert_eq!(contract.generated_by, RGC_STRUCTURED_LOGGING_BEAD_ID);
    assert_eq!(
        contract.logging_schema.event_schema_version,
        spec.event_schema_version
    );
    assert_eq!(
        contract.logging_schema.required_fields,
        spec.required_fields
    );
    assert_eq!(
        contract.logging_schema.required_correlation_ids,
        spec.required_correlation_ids
    );
    assert_eq!(
        contract.correlation_policy.correlation_key_fields,
        spec.correlation_key_fields
    );
    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        RGC_STRUCTURED_LOGGING_FAILURE_CODE
    );
    assert_eq!(
        contract.redaction_audit_contract.bead_id,
        RGC_SECRET_REDACTION_AUDIT_BEAD_ID
    );
    assert_eq!(
        contract.redaction_audit_contract.schema_version,
        RGC_SECRET_REDACTION_AUDIT_SCHEMA_VERSION
    );
    assert_eq!(
        contract.redaction_audit_contract.component,
        RGC_SECRET_REDACTION_AUDIT_COMPONENT
    );
    assert_eq!(
        contract.redaction_audit_contract.event,
        RGC_SECRET_REDACTION_AUDIT_EVENT
    );
    assert_eq!(
        contract
            .redaction_audit_contract
            .deterministic_serialization
            .serialize_fn,
        "serialize_redaction_audit_report"
    );
    assert_eq!(
        contract
            .redaction_audit_contract
            .deterministic_serialization
            .deserialize_fn,
        "deserialize_redaction_audit_report"
    );
    assert_eq!(
        contract
            .redaction_audit_contract
            .deterministic_serialization
            .hash_field,
        "report_hash"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| { line.contains("run_rgc_structured_logging_contract_gate.sh ci") }),
        "operator verification must include the RGC gate command"
    );
}

#[test]
fn rgc_054a_contract_validator_accepts_default_rgc_spec() {
    let spec = rgc_structured_logging_spec();
    assert!(
        validate_logging_contract(&spec).is_empty(),
        "default RGC contract should be valid"
    );
}

#[test]
fn rgc_054a_contract_validator_rejects_duplicate_required_fields() {
    let mut spec = rgc_structured_logging_spec();
    spec.required_fields.push("trace_id".to_string());
    let failures = validate_logging_contract(&spec);
    assert!(
        failures
            .iter()
            .any(|f| f.error_code == ValidationErrorCode::ContractValidationViolation)
    );
    assert!(
        failures
            .iter()
            .any(|f| f.message.contains("duplicate required field"))
    );
}

#[test]
fn rgc_054a_schema_evolution_rejects_removed_correlation_id() {
    let baseline = rgc_structured_logging_spec();
    let mut candidate = rgc_structured_logging_spec();
    candidate
        .required_correlation_ids
        .retain(|field| field != "trace_id");
    candidate
        .correlation_key_fields
        .retain(|field| field != "trace_id");

    let failures = validate_schema_evolution(&baseline, &candidate);
    assert!(
        failures
            .iter()
            .any(|f| f.message.contains("removed correlation field `trace_id`"))
    );
}

#[test]
fn rgc_054a_schema_evolution_accepts_additive_required_field() {
    let baseline = rgc_structured_logging_spec();
    let mut candidate = rgc_structured_logging_spec();
    candidate.required_fields.push("run_id".to_string());

    assert!(
        validate_schema_evolution(&baseline, &candidate).is_empty(),
        "additive required field should preserve backward compatibility"
    );
}

#[test]
fn rgc_054a_gate_scripts_exist_and_reference_rch() {
    let gate_path = repo_root().join("scripts/run_rgc_structured_logging_contract_gate.sh");
    let replay_path = repo_root().join("scripts/e2e/rgc_structured_logging_contract_replay.sh");

    let gate = read_to_string(&gate_path);
    let replay = read_to_string(&replay_path);

    assert!(
        gate.contains("rch exec"),
        "gate must offload heavy cargo via rch"
    );
    assert!(
        gate.contains("bd-1lsy.11.16"),
        "gate manifest should track bead id"
    );
    assert!(
        gate.contains("rch_missing_remote_exit_reason"),
        "gate must classify missing remote-exit-marker failures"
    );
    assert!(
        gate.contains("timeout-before-remote-exit-marker"),
        "gate must preserve timeout-specific missing marker attribution"
    );
    assert!(
        gate.contains("remote-exit-marker-lost-after-remote-start"),
        "gate must preserve remote-start marker-loss attribution"
    );
    assert!(
        replay.contains("run_rgc_structured_logging_contract_gate.sh"),
        "replay wrapper must route through gate script"
    );
    assert!(
        gate.contains(RGC_STRUCTURED_LOGGING_COMPONENT),
        "gate component should align with RGC contract component"
    );
}
