#![forbid(unsafe_code)]
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

use serde::Deserialize;
use serde_json::Value;

// --- RGC Structured Logging Contract ---
const STRUCTURED_LOG_JSON: &str =
    include_str!("../../../docs/rgc_structured_logging_contract_v1.json");

// --- FRX Test Logging Schema ---
const TEST_LOG_JSON: &str = include_str!("../../../docs/frx_test_logging_schema_v1.json");

// --- FRX Objective Function ---
const OBJECTIVE_JSON: &str = include_str!("../../../docs/frx_objective_function_v1.json");

// ===== Structured Logging Contract types =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct StructuredLoggingContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    logging_schema: LoggingSchema,
    correlation_policy: CorrelationPolicy,
    failure_policy: FailurePolicy,
    redaction_audit_contract: RedactionAuditContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LoggingSchema {
    event_schema_version: String,
    required_fields: Vec<String>,
    required_correlation_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CorrelationPolicy {
    correlation_key_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RedactionAuditContract {
    bead_id: String,
    schema_version: String,
    component: String,
    event: String,
    deterministic_serialization: DeterministicSerialization,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DeterministicSerialization {
    serialize_fn: String,
    deserialize_fn: String,
    hash_field: String,
}

fn parse_structured_log() -> StructuredLoggingContract {
    serde_json::from_str(STRUCTURED_LOG_JSON).expect("structured logging contract must parse")
}

// ===== Structured Logging Contract tests =====

#[test]
fn structured_log_parses_with_expected_schema() {
    let s = parse_structured_log();
    assert_eq!(s.schema_version, "rgc.structured-logging.contract.v1");
}

#[test]
fn structured_log_bead_id_is_valid() {
    let s = parse_structured_log();
    assert!(s.bead_id.starts_with("bd-"));
    assert!(s.generated_by.starts_with("bd-"));
}

#[test]
fn structured_log_required_fields_include_traceability() {
    let s = parse_structured_log();
    let fields: BTreeSet<&str> = s
        .logging_schema
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for required in [
        "trace_id",
        "decision_id",
        "policy_id",
        "scenario_id",
        "seed",
    ] {
        assert!(
            fields.contains(required),
            "missing required log field: {required}"
        );
    }
}

#[test]
fn structured_log_required_fields_are_unique() {
    let s = parse_structured_log();
    let mut seen = BTreeSet::new();
    for f in &s.logging_schema.required_fields {
        assert!(seen.insert(f.clone()), "duplicate required field: {f}");
    }
}

#[test]
fn structured_log_correlation_ids_are_subset_of_required_fields() {
    let s = parse_structured_log();
    let required: BTreeSet<&str> = s
        .logging_schema
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for cid in &s.logging_schema.required_correlation_ids {
        assert!(
            required.contains(cid.as_str()),
            "correlation id '{}' must be in required_fields",
            cid
        );
    }
}

#[test]
fn structured_log_correlation_policy_matches_schema_correlation_ids() {
    let s = parse_structured_log();
    let schema_ids: BTreeSet<&str> = s
        .logging_schema
        .required_correlation_ids
        .iter()
        .map(String::as_str)
        .collect();
    let policy_ids: BTreeSet<&str> = s
        .correlation_policy
        .correlation_key_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        schema_ids, policy_ids,
        "correlation policy key fields must match logging schema correlation ids"
    );
}

#[test]
fn structured_log_failure_policy_is_fail_closed() {
    let s = parse_structured_log();
    assert_eq!(s.failure_policy.mode, "fail_closed");
}

#[test]
fn structured_log_failure_error_code_has_fe_prefix() {
    let s = parse_structured_log();
    assert!(
        s.failure_policy.error_code.starts_with("FE-"),
        "error code must start with FE-: {}",
        s.failure_policy.error_code
    );
}

#[test]
fn structured_log_redaction_audit_has_valid_bead_id() {
    let s = parse_structured_log();
    assert!(s.redaction_audit_contract.bead_id.starts_with("bd-"));
}

#[test]
fn structured_log_redaction_serialization_functions_are_snake_case() {
    let s = parse_structured_log();
    let ds = &s.redaction_audit_contract.deterministic_serialization;
    for fname in [&ds.serialize_fn, &ds.deserialize_fn] {
        assert!(
            fname
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "serialization function must be snake_case: {fname}"
        );
    }
}

#[test]
fn structured_log_operator_verification_nonempty() {
    let s = parse_structured_log();
    assert!(!s.operator_verification.is_empty());
    assert!(
        s.operator_verification
            .iter()
            .any(|cmd| cmd.contains("structured_logging")),
        "operator verification must reference structured_logging"
    );
}

// ===== FRX Test Logging Schema types =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TestLoggingSchema {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    logging_schema: TestLoggingSchemaInner,
    correlation_policy: TestCorrelationPolicy,
    retention_policy: RetentionPolicy,
    local_semantic_links: LocalSemanticLinks,
    failure_policy: TestFailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TestLoggingSchemaInner {
    event_schema_version: String,
    required_fields: Vec<String>,
    required_correlation_ids: Vec<String>,
    required_outcomes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TestCorrelationPolicy {
    require_cross_lane_id_consistency: bool,
    correlation_key_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RetentionPolicy {
    retention_days: u64,
    redact_sensitive: bool,
    drop_secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LocalSemanticLinks {
    components: Vec<SemanticComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SemanticComponent {
    component_id: String,
    fixture_ref: String,
    trace_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TestFailurePolicy {
    mode: String,
    error_code: String,
    block_on_missing_required_fields: bool,
    block_on_correlation_mismatch: bool,
    block_on_redaction_violation: bool,
}

fn parse_test_log() -> TestLoggingSchema {
    serde_json::from_str(TEST_LOG_JSON).expect("test logging schema must parse")
}

// ===== FRX Test Logging Schema tests =====

#[test]
fn test_log_parses_with_expected_schema() {
    let t = parse_test_log();
    assert_eq!(t.schema_version, "frx.test-logging-schema.contract.v1");
}

#[test]
fn test_log_bead_id_is_valid() {
    let t = parse_test_log();
    assert!(t.bead_id.starts_with("bd-"));
    assert!(t.generated_by.starts_with("bd-"));
}

#[test]
fn test_log_required_fields_match_structured_log_fields() {
    let t = parse_test_log();
    let s = parse_structured_log();
    let test_fields: BTreeSet<&str> = t
        .logging_schema
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    let struct_fields: BTreeSet<&str> = s
        .logging_schema
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        test_fields, struct_fields,
        "test and structured logging must require the same fields"
    );
}

#[test]
fn test_log_required_outcomes_cover_pass_fail_warn() {
    let t = parse_test_log();
    let outcomes: BTreeSet<&str> = t
        .logging_schema
        .required_outcomes
        .iter()
        .map(String::as_str)
        .collect();
    for expected in ["pass", "fail", "warn"] {
        assert!(
            outcomes.contains(expected),
            "missing required outcome: {expected}"
        );
    }
}

#[test]
fn test_log_correlation_requires_cross_lane_consistency() {
    let t = parse_test_log();
    assert!(t.correlation_policy.require_cross_lane_id_consistency);
}

#[test]
fn test_log_retention_policy_is_reasonable() {
    let t = parse_test_log();
    assert!(
        t.retention_policy.retention_days >= 7 && t.retention_policy.retention_days <= 365,
        "retention_days must be 7..=365, got {}",
        t.retention_policy.retention_days
    );
    assert!(t.retention_policy.redact_sensitive);
    assert!(t.retention_policy.drop_secret);
}

#[test]
fn test_log_semantic_components_are_unique() {
    let t = parse_test_log();
    let mut seen = BTreeSet::new();
    for comp in &t.local_semantic_links.components {
        assert!(
            seen.insert(comp.component_id.clone()),
            "duplicate semantic component: {}",
            comp.component_id
        );
    }
}

#[test]
fn test_log_semantic_components_have_fixture_and_trace_refs() {
    let t = parse_test_log();
    for comp in &t.local_semantic_links.components {
        assert!(
            comp.fixture_ref.ends_with(".json"),
            "fixture_ref must be .json: {}",
            comp.fixture_ref
        );
        assert!(
            comp.trace_ref.ends_with(".json"),
            "trace_ref must be .json: {}",
            comp.trace_ref
        );
    }
}

#[test]
fn test_log_failure_policy_is_fail_closed_with_all_blocks() {
    let t = parse_test_log();
    assert_eq!(t.failure_policy.mode, "fail_closed");
    assert!(t.failure_policy.block_on_missing_required_fields);
    assert!(t.failure_policy.block_on_correlation_mismatch);
    assert!(t.failure_policy.block_on_redaction_violation);
}

#[test]
fn test_log_failure_error_code_has_fe_prefix() {
    let t = parse_test_log();
    assert!(
        t.failure_policy.error_code.starts_with("FE-"),
        "error code must start with FE-: {}",
        t.failure_policy.error_code
    );
}

#[test]
fn test_log_operator_verification_nonempty() {
    let t = parse_test_log();
    assert!(!t.operator_verification.is_empty());
    assert!(
        t.operator_verification
            .iter()
            .any(|cmd| cmd.contains("test_logging")),
        "operator verification must reference test_logging"
    );
}

// ===== FRX Objective Function types =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ObjectiveFunction {
    schema_version: String,
    status: String,
    primary_bead: String,
    generated_by: String,
    generated_at_utc: String,
    constitution_ref: String,
    constitution_version: String,
    objective: Objective,
    non_goals: Vec<String>,
    testable_invariants: Vec<TestableInvariant>,
    decision_model: DecisionModel,
    metrics: Metrics,
    downstream_reference_policy: DownstreamReferencePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Objective {
    target: String,
    dimensions: Vec<String>,
    hard_constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TestableInvariant {
    id: String,
    name: String,
    verification_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DecisionModel {
    loss_matrix_source: String,
    calibration_source: String,
    fallback_policy_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Metrics {
    north_star: Vec<Metric>,
    guardrails: Vec<Metric>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Metric {
    id: String,
    direction: String,
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DownstreamReferencePolicy {
    constitution_ref_mandatory: bool,
    required_fields: Vec<String>,
}

fn parse_objective() -> ObjectiveFunction {
    serde_json::from_str(OBJECTIVE_JSON).expect("objective function must parse")
}

// ===== FRX Objective Function tests =====

#[test]
fn objective_parses_with_expected_schema() {
    let o = parse_objective();
    assert_eq!(o.schema_version, "frx.objective_function.v1");
}

#[test]
fn objective_status_is_active() {
    let o = parse_objective();
    assert_eq!(o.status, "active");
}

#[test]
fn objective_primary_bead_is_valid() {
    let o = parse_objective();
    assert!(o.primary_bead.starts_with("bd-"));
    assert!(o.generated_by.starts_with("bd-"));
}

#[test]
fn objective_generated_at_utc_is_iso8601() {
    let o = parse_objective();
    assert!(o.generated_at_utc.ends_with('Z'));
    assert!(o.generated_at_utc.contains('T'));
}

#[test]
fn objective_target_is_maximize() {
    let o = parse_objective();
    assert_eq!(o.objective.target, "maximize");
}

#[test]
fn objective_dimensions_include_core_three() {
    let o = parse_objective();
    let dims: BTreeSet<&str> = o.objective.dimensions.iter().map(String::as_str).collect();
    for expected in ["compatibility", "deterministic_reliability", "performance"] {
        assert!(dims.contains(expected), "missing dimension: {expected}");
    }
}

#[test]
fn objective_hard_constraints_are_nonempty() {
    let o = parse_objective();
    assert!(
        o.objective.hard_constraints.len() >= 3,
        "must have at least 3 hard constraints"
    );
}

#[test]
fn objective_non_goals_are_nonempty_and_unique() {
    let o = parse_objective();
    assert!(!o.non_goals.is_empty());
    let mut seen = BTreeSet::new();
    for ng in &o.non_goals {
        assert!(!ng.trim().is_empty(), "non_goal must not be empty");
        assert!(seen.insert(ng.clone()), "duplicate non_goal: {ng}");
    }
}

#[test]
fn objective_invariant_ids_are_unique_and_frx_ci_prefixed() {
    let o = parse_objective();
    let mut seen = BTreeSet::new();
    for inv in &o.testable_invariants {
        assert!(
            inv.id.starts_with("FRX-CI-"),
            "invariant id must start with FRX-CI-: {}",
            inv.id
        );
        assert!(
            seen.insert(inv.id.clone()),
            "duplicate invariant id: {}",
            inv.id
        );
    }
}

#[test]
fn objective_invariant_count_is_5() {
    let o = parse_objective();
    assert_eq!(
        o.testable_invariants.len(),
        5,
        "must have exactly 5 testable invariants"
    );
}

#[test]
fn objective_invariant_verification_refs_are_repo_relative() {
    let o = parse_objective();
    for inv in &o.testable_invariants {
        assert!(
            !inv.verification_ref.starts_with('/'),
            "verification_ref must be repo-relative: {}",
            inv.verification_ref
        );
        assert!(
            !inv.verification_ref.contains(".."),
            "verification_ref must not traverse upward: {}",
            inv.verification_ref
        );
    }
}

#[test]
fn objective_decision_model_sources_are_repo_relative() {
    let o = parse_objective();
    for source in [
        &o.decision_model.loss_matrix_source,
        &o.decision_model.calibration_source,
        &o.decision_model.fallback_policy_source,
    ] {
        assert!(
            !source.starts_with('/'),
            "decision model source must be repo-relative: {source}"
        );
    }
}

#[test]
fn objective_north_star_metrics_are_maximize() {
    let o = parse_objective();
    assert!(
        o.metrics.north_star.len() >= 3,
        "must have at least 3 north star metrics"
    );
    for metric in &o.metrics.north_star {
        assert_eq!(
            metric.direction, "maximize",
            "north star metric {} must have direction=maximize",
            metric.id
        );
    }
}

#[test]
fn objective_guardrail_metrics_are_minimize() {
    let o = parse_objective();
    assert!(
        o.metrics.guardrails.len() >= 3,
        "must have at least 3 guardrail metrics"
    );
    for metric in &o.metrics.guardrails {
        assert_eq!(
            metric.direction, "minimize",
            "guardrail metric {} must have direction=minimize",
            metric.id
        );
    }
}

#[test]
fn objective_metric_ids_are_unique_across_both_lists() {
    let o = parse_objective();
    let mut seen = BTreeSet::new();
    for metric in o
        .metrics
        .north_star
        .iter()
        .chain(o.metrics.guardrails.iter())
    {
        assert!(
            seen.insert(metric.id.clone()),
            "duplicate metric id: {}",
            metric.id
        );
    }
}

#[test]
fn objective_downstream_policy_requires_constitution_ref() {
    let o = parse_objective();
    assert!(o.downstream_reference_policy.constitution_ref_mandatory);
}

#[test]
fn objective_downstream_required_fields_include_traceability() {
    let o = parse_objective();
    let fields: BTreeSet<&str> = o
        .downstream_reference_policy
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for required in ["trace_id", "decision_id", "policy_id"] {
        assert!(
            fields.contains(required),
            "missing downstream required field: {required}"
        );
    }
}

#[test]
fn objective_top_level_keys_match_expected() {
    let raw: Value = serde_json::from_str(OBJECTIVE_JSON).unwrap();
    let keys: BTreeSet<&str> = raw
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = BTreeSet::from([
        "schema_version",
        "status",
        "primary_bead",
        "generated_by",
        "generated_at_utc",
        "constitution_ref",
        "constitution_version",
        "objective",
        "non_goals",
        "testable_invariants",
        "decision_model",
        "metrics",
        "downstream_reference_policy",
    ]);
    assert_eq!(keys, expected);
}

#[test]
fn deterministic_double_parse_all_three() {
    assert_eq!(parse_structured_log(), parse_structured_log());
    assert_eq!(parse_test_log(), parse_test_log());
    assert_eq!(parse_objective(), parse_objective());
}
