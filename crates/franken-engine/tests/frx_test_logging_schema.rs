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

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[allow(dead_code)]
#[path = "../src/test_logging_schema.rs"]
mod test_logging_schema;

use test_logging_schema::{
    FailureTaxonomy, TEST_LOG_EVENT_SCHEMA_VERSION, TEST_LOGGING_CONTRACT_SCHEMA_VERSION,
    TEST_LOGGING_FAILURE_CODE, TestLane, TestLogEvent, TestLoggingSchemaSpec, validate_events,
};

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
struct LoggingContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    logging_schema: LoggingSchemaContract,
    correlation_policy: CorrelationPolicy,
    retention_policy: RetentionPolicyContract,
    local_semantic_links: LocalSemanticLinks,
    failure_policy: FailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LoggingSchemaContract {
    event_schema_version: String,
    required_fields: Vec<String>,
    required_correlation_ids: Vec<String>,
    required_outcomes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CorrelationPolicy {
    require_cross_lane_id_consistency: bool,
    correlation_key_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RetentionPolicyContract {
    retention_days: u16,
    redact_sensitive: bool,
    drop_secret: bool,
}

#[derive(Debug, Deserialize)]
struct LocalSemanticLinks {
    components: Vec<ComponentContractLink>,
}

#[derive(Debug, Deserialize)]
struct ComponentContractLink {
    component_id: String,
    fixture_ref: String,
    trace_ref: String,
}

#[derive(Debug, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
    block_on_missing_required_fields: bool,
    block_on_correlation_mismatch: bool,
    block_on_redaction_violation: bool,
}

fn baseline_event() -> TestLogEvent {
    TestLogEvent {
        schema_version: TEST_LOG_EVENT_SCHEMA_VERSION.to_string(),
        scenario_id: "scenario-frx-20-4".to_string(),
        fixture_id: "compat.hooks.order.state_effect_memo_ref.fixture.json".to_string(),
        trace_id: "trace-frx-20-4".to_string(),
        decision_id: "decision-frx-20-4".to_string(),
        policy_id: "policy-frx-20-4-v1".to_string(),
        lane: TestLane::Runtime,
        component: "frx_test_logging_schema".to_string(),
        event: "gate_validation".to_string(),
        outcome: "pass".to_string(),
        error_code: "none".to_string(),
        seed: 4242,
        timing_us: 150,
        timestamp_unix_ms: 1_740_000_000_000,
        failure_taxonomy: None,
    }
}

#[test]
fn frx_20_4_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_TEST_LOGGING_SCHEMA_V1.md");
    let doc = read_to_string(&path);

    let required_sections = [
        "# FRX Test Logging Schema v1",
        "## Scope",
        "## Required Event Fields",
        "## Correlation Rules",
        "## Retention and Redaction Policy",
        "## CI Gate and Failure Policy",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }

    for phrase in [
        "scenario_id",
        "fixture_id",
        "trace_id",
        "decision_id",
        "seed",
        "timing",
        "fail-closed",
        "redaction",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_20_4_contract_is_machine_readable_and_versioned() {
    let path = repo_root().join("docs/frx_test_logging_schema_v1.json");
    let contract: LoggingContract = load_json(&path);

    assert_eq!(
        contract.schema_version, TEST_LOGGING_CONTRACT_SCHEMA_VERSION,
        "contract version drift"
    );
    assert_eq!(contract.bead_id, "bd-mjh3.20.4");
    assert_eq!(contract.generated_by, "bd-mjh3.20.4");
    assert_eq!(
        contract.logging_schema.event_schema_version,
        TEST_LOG_EVENT_SCHEMA_VERSION
    );

    let spec = TestLoggingSchemaSpec::default();
    let required_fields: BTreeSet<_> = contract.logging_schema.required_fields.iter().collect();
    let expected_fields: BTreeSet<_> = spec.required_fields.iter().collect();
    assert_eq!(required_fields, expected_fields);

    let required_ids: BTreeSet<_> = contract
        .logging_schema
        .required_correlation_ids
        .iter()
        .collect();
    let expected_ids: BTreeSet<_> = spec.required_correlation_ids.iter().collect();
    assert_eq!(required_ids, expected_ids);

    assert!(
        contract
            .logging_schema
            .required_outcomes
            .iter()
            .any(|outcome| outcome == "fail")
    );
    assert!(
        contract
            .correlation_policy
            .require_cross_lane_id_consistency
    );
    assert_eq!(
        contract.correlation_policy.correlation_key_fields,
        contract.logging_schema.required_correlation_ids
    );

    assert!(contract.retention_policy.redact_sensitive);
    assert!(contract.retention_policy.drop_secret);
    assert!(contract.retention_policy.retention_days >= 30);

    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        TEST_LOGGING_FAILURE_CODE
    );
    assert!(contract.failure_policy.block_on_missing_required_fields);
    assert!(contract.failure_policy.block_on_correlation_mismatch);
    assert!(contract.failure_policy.block_on_redaction_violation);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_frx_test_logging_schema_suite.sh ci")),
        "operator verification must include CI gate command"
    );
}

#[test]
fn frx_20_4_links_reference_existing_fixture_and_trace_contracts() {
    let path = repo_root().join("docs/frx_test_logging_schema_v1.json");
    let contract: LoggingContract = load_json(&path);

    let fixtures_root =
        repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/fixtures");
    let traces_root =
        repo_root().join("crates/franken-engine/tests/conformance/frx_react_corpus/traces");

    assert!(
        !contract.local_semantic_links.components.is_empty(),
        "local semantic links must not be empty"
    );

    let mut component_ids = BTreeSet::new();
    for link in contract.local_semantic_links.components {
        assert!(component_ids.insert(link.component_id.clone()));
        let fixture_path = fixtures_root.join(&link.fixture_ref);
        let trace_path = traces_root.join(&link.trace_ref);
        assert!(
            fixture_path.is_file(),
            "missing fixture contract: {}",
            fixture_path.display()
        );
        assert!(
            trace_path.is_file(),
            "missing trace contract: {}",
            trace_path.display()
        );
    }
}

#[test]
fn frx_20_4_validation_report_is_fail_closed_on_missing_required_fields() {
    let mut event = baseline_event();
    event.fixture_id.clear();
    event.failure_taxonomy = Some(FailureTaxonomy::SchemaDrift);

    let report = validate_events(&[event]);
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
    assert_eq!(report.error_code, TEST_LOGGING_FAILURE_CODE);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.message.contains("fixture_id"))
    );
}

#[test]
fn frx_20_4_validation_report_detects_cross_lane_correlation_mismatch() {
    let event_a = baseline_event();
    let mut event_b = baseline_event();
    event_b.lane = TestLane::Compiler;
    event_b.trace_id = "trace-frx-20-4-mismatch".to_string();

    let report = validate_events(&[event_a, event_b]);
    assert!(!report.valid);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.message.contains("trace_id"))
    );
}

#[test]
fn frx_20_4_validation_report_passes_on_consistent_cross_lane_events() {
    let event_a = baseline_event();
    let mut event_b = baseline_event();
    event_b.lane = TestLane::Router;
    event_b.event = "router_validation".to_string();

    let report = validate_events(&[event_a, event_b]);
    assert!(report.valid);
    assert_eq!(report.outcome, "pass");
    assert_eq!(report.error_code, "none");
}

// ---------- baseline_event helper ----------

#[test]
fn baseline_event_sets_correct_fields() {
    let event = baseline_event();
    assert_eq!(event.schema_version, TEST_LOG_EVENT_SCHEMA_VERSION);
    assert_eq!(event.lane, TestLane::Runtime);
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_code, "none");
    assert!(event.failure_taxonomy.is_none());
    assert!(event.seed > 0);
}

// ---------- TestLane ----------

#[test]
fn test_lane_serde_roundtrip() {
    for lane in [TestLane::Runtime, TestLane::Compiler, TestLane::Router] {
        let json = serde_json::to_string(&lane).expect("serialize");
        let recovered: TestLane = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, lane);
    }
}

// ---------- FailureTaxonomy ----------

#[test]
fn failure_taxonomy_serde_roundtrip() {
    let taxonomy = FailureTaxonomy::SchemaDrift;
    let json = serde_json::to_string(&taxonomy).expect("serialize");
    let recovered: FailureTaxonomy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, taxonomy);
}

// ---------- TestLogEvent ----------

#[test]
fn test_log_event_serde_roundtrip() {
    let event = baseline_event();
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: TestLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-frx-20-4");
    assert_eq!(recovered.lane, TestLane::Runtime);
}

#[test]
fn test_log_event_correlation_key_matches_trace() {
    let event = baseline_event();
    let key = event.correlation_key();
    assert!(key.contains("trace-frx-20-4"));
}

// ---------- TestLoggingSchemaSpec ----------

#[test]
fn schema_spec_default_has_required_fields() {
    let spec = TestLoggingSchemaSpec::default();
    assert!(!spec.required_fields.is_empty());
    assert!(spec.required_fields.contains(&"trace_id".to_string()));
    assert!(spec.required_fields.contains(&"outcome".to_string()));
}

#[test]
fn schema_spec_default_has_correlation_ids() {
    let spec = TestLoggingSchemaSpec::default();
    assert!(!spec.required_correlation_ids.is_empty());
}

// ---------- validate_events ----------

#[test]
fn validate_events_single_valid_event_passes() {
    let event = baseline_event();
    let report = validate_events(&[event]);
    assert!(report.valid);
    assert_eq!(report.outcome, "pass");
}

#[test]
fn validate_events_empty_trace_id_fails() {
    let mut event = baseline_event();
    event.trace_id.clear();
    let report = validate_events(&[event]);
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
}

// ---------- schema version constants ----------

#[test]
fn schema_version_constants_are_nonempty() {
    assert!(!TEST_LOG_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!TEST_LOGGING_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!TEST_LOGGING_FAILURE_CODE.is_empty());
}

// ---------- validation report determinism ----------

#[test]
fn validation_report_is_deterministic() {
    let events = vec![baseline_event()];
    let a = validate_events(&events);
    let b = validate_events(&events);
    assert_eq!(a.valid, b.valid);
    assert_eq!(a.outcome, b.outcome);
    assert_eq!(a.failures.len(), b.failures.len());
}

#[test]
fn test_lane_all_variants_serialize() {
    for lane in [TestLane::Runtime, TestLane::Compiler, TestLane::Router] {
        let json = serde_json::to_string(&lane).expect("serialize");
        assert!(!json.is_empty());
    }
}

#[test]
fn failure_taxonomy_all_variants_roundtrip() {
    for taxonomy in [
        FailureTaxonomy::SchemaDrift,
        FailureTaxonomy::DeterminismDrift,
        FailureTaxonomy::InvariantViolation,
        FailureTaxonomy::Timeout,
        FailureTaxonomy::ResourceBudget,
        FailureTaxonomy::Unknown,
    ] {
        let json = serde_json::to_string(&taxonomy).expect("serialize");
        let recovered: FailureTaxonomy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, taxonomy);
    }
}

#[test]
fn validate_events_empty_list_returns_report() {
    let report = validate_events(&[]);
    // Empty list may fail (no events) or pass depending on implementation
    // Just verify a report is returned with a valid outcome string
    assert!(!report.outcome.is_empty());
}

#[test]
fn test_lane_all_variants_roundtrip() {
    for lane in [TestLane::Runtime, TestLane::Compiler, TestLane::Router] {
        let json = serde_json::to_string(&lane).expect("serialize");
        let recovered: TestLane = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, lane);
    }
}

#[test]
fn failure_taxonomy_debug_is_nonempty() {
    for taxonomy in [
        FailureTaxonomy::SchemaDrift,
        FailureTaxonomy::Timeout,
        FailureTaxonomy::Unknown,
    ] {
        let s = format!("{taxonomy:?}");
        assert!(!s.is_empty());
    }
}

#[test]
fn validate_events_deterministic_for_single_event() {
    let event = baseline_event();
    let a = validate_events(std::slice::from_ref(&event));
    let b = validate_events(&[event]);
    assert_eq!(a.valid, b.valid);
    assert_eq!(a.outcome, b.outcome);
}

#[test]
fn validate_events_empty_decision_id_fails() {
    let mut event = baseline_event();
    event.decision_id.clear();
    let report = validate_events(&[event]);
    assert!(!report.valid);
    assert_eq!(report.outcome, "fail");
}

#[test]
fn validate_events_empty_scenario_id_fails() {
    let mut event = baseline_event();
    event.scenario_id.clear();
    let report = validate_events(&[event]);
    assert!(!report.valid);
}

#[test]
fn validate_events_empty_policy_id_fails() {
    let mut event = baseline_event();
    event.policy_id.clear();
    let report = validate_events(&[event]);
    assert!(!report.valid);
}

#[test]
fn test_logging_failure_code_starts_with_fe() {
    assert!(TEST_LOGGING_FAILURE_CODE.starts_with("FE-"));
}

#[test]
fn baseline_event_has_positive_timing() {
    let event = baseline_event();
    assert!(event.timing_us > 0);
    assert!(event.timestamp_unix_ms > 0);
}

#[test]
fn schema_spec_default_serde_roundtrip() {
    let spec = TestLoggingSchemaSpec::default();
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: TestLoggingSchemaSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.required_fields, spec.required_fields);
}

#[test]
fn test_logging_schema_spec_debug_is_nonempty() {
    let spec = TestLoggingSchemaSpec::default();
    assert!(!format!("{spec:?}").is_empty());
}

#[test]
fn test_log_event_debug_is_nonempty() {
    let event = baseline_event();
    assert!(!format!("{event:?}").is_empty());
}

#[test]
fn failure_taxonomy_serde_is_deterministic() {
    let tax = FailureTaxonomy::Unknown;
    let a = serde_json::to_string(&tax).expect("first");
    let b = serde_json::to_string(&tax).expect("second");
    assert_eq!(a, b);
}
