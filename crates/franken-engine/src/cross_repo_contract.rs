//! Cross-repo contract tests validating schema/API compatibility for
//! integration boundaries between FrankenEngine and sibling repos.
//!
//! Every declared integration boundary (`frankentui`, `frankensqlite`,
//! `fastapi_rust`/service endpoints) must have at least one contract test
//! proving that serialized representations are stable, error codes are
//! machine-readable, and API envelopes satisfy schema invariants.
//!
//! Plan reference: Section 10.14 item 12 (`bd-rr94`).
//! Cross-refs: 10.15 (advanced cross-repo conformance lab),
//! Section 13 (cross-repo conformance lab pass is release gate).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::frankentui_adapter::FRANKENTUI_ADAPTER_SCHEMA_VERSION;
use crate::storage_adapter::STORAGE_SCHEMA_VERSION;

// ---------------------------------------------------------------------------
// Regression classification
// ---------------------------------------------------------------------------

/// Classification of a contract violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RegressionClass {
    /// Serialized shape changed — wire-incompatible.
    Breaking,
    /// Observable behavior changed (ordering, defaults, error messages).
    Behavioral,
    /// Structured log or telemetry field changed.
    Observability,
    /// Performance SLO regression (latency, throughput, memory).
    Performance,
}

impl fmt::Display for RegressionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Breaking => f.write_str("BREAKING"),
            Self::Behavioral => f.write_str("BEHAVIORAL"),
            Self::Observability => f.write_str("OBSERVABILITY"),
            Self::Performance => f.write_str("PERFORMANCE"),
        }
    }
}

/// A single contract violation detected during verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractViolation {
    pub boundary: String,
    pub contract_name: String,
    pub regression_class: RegressionClass,
    pub detail: String,
}

impl fmt::Display for ContractViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}/{}: {}",
            self.regression_class, self.boundary, self.contract_name, self.detail
        )
    }
}

// ---------------------------------------------------------------------------
// Schema contract: field presence + type assertions on serialized JSON
// ---------------------------------------------------------------------------

/// Declares expected top-level fields for a serialized type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaContract {
    pub boundary: String,
    pub type_name: String,
    pub required_fields: BTreeSet<String>,
    pub field_types: BTreeMap<String, FieldType>,
}

/// Expected JSON value type for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FieldType {
    String,
    Number,
    Bool,
    Array,
    Object,
    Null,
}

impl FieldType {
    fn matches(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Bool => value.is_boolean(),
            Self::Array => value.is_array(),
            Self::Object => value.is_object(),
            Self::Null => value.is_null(),
        }
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => f.write_str("string"),
            Self::Number => f.write_str("number"),
            Self::Bool => f.write_str("bool"),
            Self::Array => f.write_str("array"),
            Self::Object => f.write_str("object"),
            Self::Null => f.write_str("null"),
        }
    }
}

impl SchemaContract {
    /// Verify a serialized JSON value against this contract.
    pub fn verify(&self, json: &Value) -> Vec<ContractViolation> {
        let mut violations = Vec::new();
        let obj = match json.as_object() {
            Some(obj) => obj,
            None => {
                violations.push(ContractViolation {
                    boundary: self.boundary.clone(),
                    contract_name: self.type_name.clone(),
                    regression_class: RegressionClass::Breaking,
                    detail: "expected JSON object at top level".to_string(),
                });
                return violations;
            }
        };

        for field in &self.required_fields {
            if !obj.contains_key(field.as_str()) {
                violations.push(ContractViolation {
                    boundary: self.boundary.clone(),
                    contract_name: self.type_name.clone(),
                    regression_class: RegressionClass::Breaking,
                    detail: format!("missing required field `{field}`"),
                });
            }
        }

        for (field, expected_type) in &self.field_types {
            if let Some(value) = obj.get(field.as_str())
                && !value.is_null()
                && !expected_type.matches(value)
            {
                violations.push(ContractViolation {
                    boundary: self.boundary.clone(),
                    contract_name: self.type_name.clone(),
                    regression_class: RegressionClass::Breaking,
                    detail: format!(
                        "field `{field}` expected type {expected_type}, got {}",
                        json_type_name(value)
                    ),
                });
            }
        }

        violations
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// Structured log contract
// ---------------------------------------------------------------------------

/// Canonical log field keys required by Section 10.14 contracts.
pub const REQUIRED_LOG_FIELDS: &[&str] = &["trace_id", "component", "event", "outcome"];

/// Optional but recommended structured log fields.
pub const OPTIONAL_LOG_FIELDS: &[&str] = &["decision_id", "policy_id", "error_code"];

/// Verify that a structured log event JSON contains all required fields.
pub fn verify_structured_log(json: &Value, boundary: &str) -> Vec<ContractViolation> {
    let mut violations = Vec::new();
    let obj = match json.as_object() {
        Some(obj) => obj,
        None => {
            violations.push(ContractViolation {
                boundary: boundary.to_string(),
                contract_name: "structured_log".to_string(),
                regression_class: RegressionClass::Observability,
                detail: "log event must be a JSON object".to_string(),
            });
            return violations;
        }
    };

    for field in REQUIRED_LOG_FIELDS {
        if !obj.contains_key(*field) {
            violations.push(ContractViolation {
                boundary: boundary.to_string(),
                contract_name: "structured_log".to_string(),
                regression_class: RegressionClass::Observability,
                detail: format!("missing required log field `{field}`"),
            });
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Error code contract
// ---------------------------------------------------------------------------

/// Verify an error code matches the stable prefix format.
pub fn verify_error_code_format(code: &str, expected_prefix: &str) -> bool {
    code.starts_with(expected_prefix)
}

// ---------------------------------------------------------------------------
// Boundary contract builders
// ---------------------------------------------------------------------------

/// Build the schema contract for `AdapterEnvelope` (frankentui boundary).
pub fn frankentui_envelope_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in [
        "schema_version",
        "trace_id",
        "generated_at_unix_ms",
        "stream",
        "update_kind",
        "payload",
    ] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("schema_version".to_string(), FieldType::Number);
    types.insert("trace_id".to_string(), FieldType::String);
    types.insert("generated_at_unix_ms".to_string(), FieldType::Number);
    types.insert("stream".to_string(), FieldType::String);
    types.insert("update_kind".to_string(), FieldType::String);
    types.insert("payload".to_string(), FieldType::Object);

    SchemaContract {
        boundary: "frankentui".to_string(),
        type_name: "AdapterEnvelope".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `StoreRecord` (frankensqlite boundary).
pub fn frankensqlite_store_record_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in ["store", "key", "value", "metadata", "revision"] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("store".to_string(), FieldType::String);
    types.insert("key".to_string(), FieldType::String);
    types.insert("value".to_string(), FieldType::Array);
    types.insert("metadata".to_string(), FieldType::Object);
    types.insert("revision".to_string(), FieldType::Number);

    SchemaContract {
        boundary: "frankensqlite".to_string(),
        type_name: "StoreRecord".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `EndpointResponse` (fastapi_rust boundary).
pub fn fastapi_endpoint_response_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in ["status", "endpoint", "trace_id", "request_id", "log"] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("status".to_string(), FieldType::String);
    types.insert("endpoint".to_string(), FieldType::String);
    types.insert("trace_id".to_string(), FieldType::String);
    types.insert("request_id".to_string(), FieldType::String);
    types.insert("log".to_string(), FieldType::Object);

    SchemaContract {
        boundary: "fastapi_rust".to_string(),
        type_name: "EndpointResponse".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `StorageEvent` (frankensqlite telemetry).
pub fn frankensqlite_storage_event_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
    ] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("trace_id".to_string(), FieldType::String);
    types.insert("decision_id".to_string(), FieldType::String);
    types.insert("policy_id".to_string(), FieldType::String);
    types.insert("component".to_string(), FieldType::String);
    types.insert("event".to_string(), FieldType::String);
    types.insert("outcome".to_string(), FieldType::String);

    SchemaContract {
        boundary: "frankensqlite".to_string(),
        type_name: "StorageEvent".to_string(),
        required_fields: required,
        field_types: types,
    }
}

/// Build the schema contract for `MigrationReceipt` (frankensqlite boundary).
pub fn frankensqlite_migration_receipt_contract() -> SchemaContract {
    let mut required = BTreeSet::new();
    for field in [
        "backend",
        "from_version",
        "to_version",
        "stores_touched",
        "records_touched",
        "state_hash_before",
        "state_hash_after",
    ] {
        required.insert(field.to_string());
    }

    let mut types = BTreeMap::new();
    types.insert("backend".to_string(), FieldType::String);
    types.insert("from_version".to_string(), FieldType::Number);
    types.insert("to_version".to_string(), FieldType::Number);
    types.insert("stores_touched".to_string(), FieldType::Array);
    types.insert("records_touched".to_string(), FieldType::Number);
    types.insert("state_hash_before".to_string(), FieldType::String);
    types.insert("state_hash_after".to_string(), FieldType::String);

    SchemaContract {
        boundary: "frankensqlite".to_string(),
        type_name: "MigrationReceipt".to_string(),
        required_fields: required,
        field_types: types,
    }
}

// ---------------------------------------------------------------------------
// Deterministic verification helpers
// ---------------------------------------------------------------------------

/// Verify that two independent serializations of the same value produce
/// identical bytes (deterministic serde round-trip).
pub fn verify_deterministic_serde<T>(value: &T) -> Result<(), String>
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug,
{
    let bytes_a = serde_json::to_vec(value).map_err(|err| format!("serialize A: {err}"))?;
    let bytes_b = serde_json::to_vec(value).map_err(|err| format!("serialize B: {err}"))?;
    if bytes_a != bytes_b {
        return Err("non-deterministic: two serializations differ".to_string());
    }

    let decoded: T =
        serde_json::from_slice(&bytes_a).map_err(|err| format!("deserialize: {err}"))?;
    if decoded != *value {
        return Err("round-trip produced different value".to_string());
    }

    let bytes_c = serde_json::to_vec(&decoded).map_err(|err| format!("serialize C: {err}"))?;
    if bytes_a != bytes_c {
        return Err("round-trip serialization not stable".to_string());
    }

    Ok(())
}

/// Verify that a contract-covered type serializes to a schema-compliant JSON.
pub fn verify_schema_compliance<T: Serialize>(
    value: &T,
    contract: &SchemaContract,
) -> Vec<ContractViolation> {
    match serde_json::to_value(value) {
        Ok(json) => contract.verify(&json),
        Err(err) => vec![ContractViolation {
            boundary: contract.boundary.clone(),
            contract_name: contract.type_name.clone(),
            regression_class: RegressionClass::Breaking,
            detail: format!("serialization failed: {err}"),
        }],
    }
}

// ---------------------------------------------------------------------------
// Version compatibility registry
// ---------------------------------------------------------------------------

/// Known version pairs for cross-repo compatibility tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionCompatibilityEntry {
    pub boundary: String,
    pub current_version: u32,
    pub minimum_compatible_version: u32,
}

/// Build the version compatibility registry for all boundaries.
pub fn version_compatibility_registry() -> Vec<VersionCompatibilityEntry> {
    vec![
        VersionCompatibilityEntry {
            boundary: "frankentui".to_string(),
            current_version: FRANKENTUI_ADAPTER_SCHEMA_VERSION,
            minimum_compatible_version: 1,
        },
        VersionCompatibilityEntry {
            boundary: "frankensqlite".to_string(),
            current_version: STORAGE_SCHEMA_VERSION,
            minimum_compatible_version: 1,
        },
        VersionCompatibilityEntry {
            boundary: "fastapi_rust".to_string(),
            current_version: 1,
            minimum_compatible_version: 1,
        },
    ]
}

// ---------------------------------------------------------------------------
// Integration point inventory
// ---------------------------------------------------------------------------

/// All declared integration points across sibling repo boundaries.
pub fn integration_point_inventory() -> BTreeMap<String, Vec<String>> {
    let mut inventory = BTreeMap::new();

    inventory.insert(
        "frankentui".to_string(),
        vec![
            "AdapterEnvelope".to_string(),
            "FrankentuiViewPayload".to_string(),
            "IncidentReplayView".to_string(),
            "PolicyExplanationCardView".to_string(),
            "ControlDashboardView".to_string(),
            "ControlPlaneInvariantsDashboardView".to_string(),
            "FlowDecisionDashboardView".to_string(),
            "CapabilityDeltaDashboardView".to_string(),
            "ReplacementProgressDashboardView".to_string(),
            "ProofSpecializationLineageDashboardView".to_string(),
        ],
    );

    inventory.insert(
        "frankensqlite".to_string(),
        vec![
            "StoreRecord".to_string(),
            "StoreQuery".to_string(),
            "BatchPutEntry".to_string(),
            "MigrationReceipt".to_string(),
            "StorageEvent".to_string(),
            "FrankensqliteBackend".to_string(),
        ],
    );

    inventory.insert(
        "fastapi_rust".to_string(),
        vec![
            "EndpointResponse".to_string(),
            "ErrorEnvelope".to_string(),
            "HealthStatusResponse".to_string(),
            "ControlActionRequest".to_string(),
            "ControlActionResponse".to_string(),
            "EvidenceExportRequest".to_string(),
            "EvidenceExportResponse".to_string(),
            "ReplayControlRequest".to_string(),
            "ReplayControlResponse".to_string(),
        ],
    );

    inventory
}

// ---------------------------------------------------------------------------
// Contract suite runner
// ---------------------------------------------------------------------------

/// Result of running the full contract verification suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSuiteResult {
    pub total_contracts: usize,
    pub passed: usize,
    pub failed: usize,
    pub violations: Vec<ContractViolation>,
    pub boundaries_covered: BTreeSet<String>,
}

impl ContractSuiteResult {
    pub fn is_passing(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for ContractSuiteResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "contracts={} passed={} failed={} boundaries={}",
            self.total_contracts,
            self.passed,
            self.failed,
            self.boundaries_covered.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::frankentui_adapter::{
        ActiveSpecializationRowView, AdapterEnvelope, AdapterStream, BenchmarkTrendPointView,
        BlockedFlowView, CancellationEventView, CancellationKind, ConfinementProofView,
        ConfinementStatus, ControlDashboardView, ControlPlaneInvariantsDashboardView,
        ControlPlaneInvariantsPartial, CurrentCapabilityDeltaRowView, DashboardAlertMetric,
        DashboardAlertRule, DashboardMetricView, DashboardSeverity, DecisionOutcomeKind,
        DeclassificationDecisionView, DeclassificationOutcome, ExtensionStatusRow,
        FlowDecisionDashboardView, FlowDecisionPartial, FlowProofCoverageView,
        FlowSensitivityLevel, FrankentuiViewPayload, GrantExpiryStatus, IncidentReplayView,
        LabelMapEdgeView, LabelMapNodeView, LabelMapView, ObligationState, ObligationStatusRowView,
        OverrideRationaleView, OverrideReviewStatus, PolicyExplanationCardView,
        PolicyExplanationPartial, ProofInventoryKind, ProofInventoryRowView,
        ProofSpecializationInvalidationReason, ProofSpecializationLineageDashboardView,
        ProofSpecializationLineagePartial, ProofValidityStatus,
        ProposedMinimalCapabilityDeltaRowView, RecoveryStatus, RegionLifecycleRowView,
        ReplacementOpportunityInput, ReplacementProgressDashboardView, ReplacementProgressPartial,
        ReplacementRiskLevel, ReplayEventView, ReplayHealthPanelView, ReplayHealthStatus,
        ReplayStatus, SafeModeActivationView, SchemaCompatibilityStatus, SchemaVersionPanelView,
        SlotStatusOverviewRow, SpecializationFallbackEventView, SpecializationFallbackReason,
        SpecializationInvalidationRowView, ThresholdComparator, UpdateKind,
    };
    use crate::policy_controller::service_endpoint_template::{
        AuthContext, ControlAction, EndpointResponse, ErrorEnvelope, HealthStatusResponse,
        ReplayCommand, RequestContext, SCOPE_CONTROL_WRITE, SCOPE_EVIDENCE_READ, SCOPE_HEALTH_READ,
        SCOPE_REPLAY_READ, SCOPE_REPLAY_WRITE, StructuredLogEvent,
    };
    use crate::storage_adapter::{
        EventContext, InMemoryStorageAdapter, MigrationReceipt, StorageAdapter, StorageError,
        StorageEvent, StoreKind, StoreQuery, StoreRecord,
    };

    // ── frankentui boundary ────────────────────────────────────────────

    fn sample_envelope() -> AdapterEnvelope {
        let replay = IncidentReplayView::snapshot(
            "trace-contract-1",
            "contract-scenario",
            vec![ReplayEventView::new(
                1,
                "engine",
                "startup",
                "ok",
                1_700_000_000_000,
            )],
        );
        AdapterEnvelope::new(
            "trace-contract-1",
            1_700_000_000_000,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            FrankentuiViewPayload::IncidentReplay(replay),
        )
    }

    #[test]
    fn frankentui_envelope_schema_compliance() {
        let contract = frankentui_envelope_contract();
        let envelope = sample_envelope();
        let violations = verify_schema_compliance(&envelope, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankentui_envelope_deterministic_serde() {
        let envelope = sample_envelope();
        verify_deterministic_serde(&envelope).expect("must be deterministic");
    }

    #[test]
    fn frankentui_envelope_schema_version_matches_current() {
        let envelope = sample_envelope();
        assert_eq!(envelope.schema_version, FRANKENTUI_ADAPTER_SCHEMA_VERSION);
    }

    #[test]
    fn frankentui_all_payload_variants_serialize() {
        let replay = FrankentuiViewPayload::IncidentReplay(IncidentReplayView::snapshot(
            "trace-1",
            "scenario-1",
            vec![],
        ));
        let policy = FrankentuiViewPayload::PolicyExplanation(
            PolicyExplanationCardView::from_partial(PolicyExplanationPartial {
                decision_id: "d-1".to_string(),
                policy_id: "p-1".to_string(),
                selected_action: "allow".to_string(),
                ..Default::default()
            }),
        );
        let dashboard = FrankentuiViewPayload::ControlDashboard(ControlDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east".to_string(),
            security_epoch: 5,
            runtime_mode: "secure".to_string(),
            metrics: vec![DashboardMetricView {
                metric: "p95_ms".to_string(),
                value: 42,
                unit: "ms".to_string(),
            }],
            extension_rows: vec![ExtensionStatusRow {
                extension_id: "ext-a".to_string(),
                state: "running".to_string(),
                trust_level: "verified".to_string(),
            }],
            incident_counts: BTreeMap::new(),
        });
        let replacement = FrankentuiViewPayload::ReplacementProgressDashboard(
            ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
                cluster: "prod".to_string(),
                zone: "us-east".to_string(),
                security_epoch: Some(5),
                generated_at_unix_ms: Some(1_700_000_000_111),
                slot_status_overview: vec![SlotStatusOverviewRow {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    implementation_kind: "delegate".to_string(),
                    promotion_status: "promotion_candidate".to_string(),
                    risk_level: ReplacementRiskLevel::High,
                    last_transition_unix_ms: 1_700_000_000_100,
                    health: "blocked".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                }],
                replacement_inputs: vec![ReplacementOpportunityInput {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    performance_uplift_millionths: 400_000,
                    invocation_frequency_per_minute: 120,
                    risk_reduction_millionths: 200_000,
                }],
                ..Default::default()
            }),
        );
        let invariants = FrankentuiViewPayload::ControlPlaneInvariantsDashboard(Box::new(
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-east".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_000_222),
                evidence_stream: vec![crate::frankentui_adapter::EvidenceStreamEntryView {
                    trace_id: "trace-inv-1".to_string(),
                    decision_id: "decision-inv-1".to_string(),
                    policy_id: "policy-1".to_string(),
                    action_type: "fallback".to_string(),
                    decision_outcome: DecisionOutcomeKind::Fallback,
                    expected_loss_millionths: 100_000,
                    extension_id: "ext-a".to_string(),
                    region_id: "region-a".to_string(),
                    severity: DashboardSeverity::Warning,
                    component: "guardplane".to_string(),
                    event: "safe_mode_activated".to_string(),
                    outcome: "fallback".to_string(),
                    error_code: Some("FE-SAFE-001".to_string()),
                    timestamp_unix_ms: 1_700_000_000_200,
                }],
                obligation_rows: vec![ObligationStatusRowView {
                    obligation_id: "obl-1".to_string(),
                    extension_id: "ext-a".to_string(),
                    region_id: "region-a".to_string(),
                    state: ObligationState::Failed,
                    severity: DashboardSeverity::Critical,
                    due_at_unix_ms: 1_700_000_001_000,
                    updated_at_unix_ms: 1_700_000_000_210,
                    detail: "replay divergence".to_string(),
                }],
                region_rows: vec![RegionLifecycleRowView {
                    region_id: "region-a".to_string(),
                    is_active: true,
                    active_extensions: 1,
                    created_at_unix_ms: 1_700_000_000_000,
                    closed_at_unix_ms: None,
                    quiescent_close_time_ms: None,
                }],
                cancellation_events: vec![CancellationEventView {
                    extension_id: "ext-a".to_string(),
                    region_id: "region-a".to_string(),
                    cancellation_kind: CancellationKind::Quarantine,
                    severity: DashboardSeverity::Critical,
                    detail: "containment escalation".to_string(),
                    timestamp_unix_ms: 1_700_000_000_205,
                }],
                replay_health: Some(ReplayHealthPanelView {
                    last_run_status: ReplayHealthStatus::Fail,
                    divergence_count: 1,
                    last_replay_timestamp_unix_ms: Some(1_700_000_000_190),
                }),
                benchmark_points: vec![BenchmarkTrendPointView {
                    timestamp_unix_ms: 1_700_000_000_180,
                    throughput_tps: 1_950,
                    latency_p95_ms: 130,
                    memory_peak_mb: 760,
                }],
                throughput_floor_tps: Some(2_000),
                latency_p95_ceiling_ms: Some(120),
                memory_peak_ceiling_mb: Some(750),
                safe_mode_activations: vec![SafeModeActivationView {
                    activation_id: "sm-1".to_string(),
                    activation_type: "replay_divergence".to_string(),
                    extension_id: "ext-a".to_string(),
                    region_id: "region-a".to_string(),
                    severity: DashboardSeverity::Critical,
                    recovery_status: RecoveryStatus::Recovering,
                    activated_at_unix_ms: 1_700_000_000_202,
                    recovered_at_unix_ms: None,
                }],
                schema_version: Some(SchemaVersionPanelView {
                    evidence_schema_version: 4,
                    last_migration_unix_ms: Some(1_699_999_999_000),
                    compatibility_status: SchemaCompatibilityStatus::Compatible,
                }),
                alert_rules: vec![DashboardAlertRule {
                    rule_id: "alert-fallback".to_string(),
                    description: "fallback activations > 0".to_string(),
                    metric: DashboardAlertMetric::FallbackActivationCount,
                    comparator: ThresholdComparator::GreaterThan,
                    threshold: 0,
                    severity: DashboardSeverity::Critical,
                }],
                ..Default::default()
            }),
        ));
        let flow = FrankentuiViewPayload::FlowDecisionDashboard(
            FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
                cluster: "prod".to_string(),
                zone: "us-east".to_string(),
                security_epoch: Some(7),
                generated_at_unix_ms: Some(1_700_000_000_333),
                label_map: LabelMapView {
                    nodes: vec![
                        LabelMapNodeView {
                            label_id: "pii".to_string(),
                            sensitivity: FlowSensitivityLevel::High,
                            description: "user pii".to_string(),
                            extension_overlays: vec!["ext-a".to_string()],
                        },
                        LabelMapNodeView {
                            label_id: "public".to_string(),
                            sensitivity: FlowSensitivityLevel::Low,
                            description: "public data".to_string(),
                            extension_overlays: vec!["ext-a".to_string()],
                        },
                    ],
                    edges: vec![LabelMapEdgeView {
                        source_label: "pii".to_string(),
                        sink_clearance: "high".to_string(),
                        route_policy_id: Some("policy-ifc-1".to_string()),
                        route_enabled: true,
                    }],
                },
                blocked_flows: vec![BlockedFlowView {
                    flow_id: "flow-1".to_string(),
                    extension_id: "ext-a".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    sensitivity: FlowSensitivityLevel::Critical,
                    blocked_reason: "sink clearance mismatch".to_string(),
                    attempted_exfiltration: true,
                    code_path_ref: "src/ext_a/main.ts:90".to_string(),
                    extension_context_ref: "frankentui://extension/ext-a".to_string(),
                    trace_id: "trace-flow-1".to_string(),
                    decision_id: "decision-flow-1".to_string(),
                    policy_id: "policy-ifc-1".to_string(),
                    error_code: Some("FE-IFC-BLOCK".to_string()),
                    occurred_at_unix_ms: 1_700_000_000_320,
                }],
                declassification_history: vec![DeclassificationDecisionView {
                    decision_id: "decl-1".to_string(),
                    extension_id: "ext-a".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    sensitivity: FlowSensitivityLevel::Critical,
                    outcome: DeclassificationOutcome::Denied,
                    policy_id: "policy-ifc-1".to_string(),
                    loss_assessment_summary: "expected loss too high".to_string(),
                    rationale: "deny".to_string(),
                    receipt_ref: "frankentui://declassification/decl-1".to_string(),
                    replay_ref: "frankentui://replay/decl-1".to_string(),
                    decided_at_unix_ms: 1_700_000_000_321,
                }],
                confinement_proofs: vec![ConfinementProofView {
                    extension_id: "ext-a".to_string(),
                    status: ConfinementStatus::Partial,
                    covered_flow_count: 5,
                    uncovered_flow_count: 1,
                    proof_rows: vec![FlowProofCoverageView {
                        proof_id: "proof-1".to_string(),
                        source_label: "pii".to_string(),
                        sink_clearance: "external".to_string(),
                        covered: false,
                        proof_ref: "frankentui://proof/proof-1".to_string(),
                    }],
                    uncovered_flow_refs: vec!["frankentui://flow/flow-1".to_string()],
                }],
                blocked_flow_alert_threshold: Some(1),
                ..Default::default()
            }),
        );
        let capability_delta = FrankentuiViewPayload::CapabilityDeltaDashboard(
            crate::frankentui_adapter::CapabilityDeltaDashboardView::from_partial(
                crate::frankentui_adapter::CapabilityDeltaPartial {
                    cluster: "prod".to_string(),
                    zone: "us-east".to_string(),
                    security_epoch: Some(8),
                    generated_at_unix_ms: Some(1_700_000_000_430),
                    current_capability_rows: vec![CurrentCapabilityDeltaRowView {
                        extension_id: "ext-a".to_string(),
                        witness_id: "witness-a".to_string(),
                        policy_id: "policy-a".to_string(),
                        witness_epoch: 8,
                        lifecycle_state: "active".to_string(),
                        active_witness_capabilities: vec![
                            "fs.read".to_string(),
                            "network.fetch".to_string(),
                        ],
                        manifest_declared_capabilities: vec!["fs.read".to_string()],
                        over_privileged_capabilities: vec!["network.fetch".to_string()],
                        over_privilege_ratio_millionths: 0,
                        over_privilege_replay_ref: "frankentui://replay/witness/witness-a"
                            .to_string(),
                        latest_receipt_timestamp_ns: Some(1_700_000_000_420_000_000),
                    }],
                    proposed_minimal_rows: vec![ProposedMinimalCapabilityDeltaRowView {
                        extension_id: "ext-a".to_string(),
                        witness_id: "witness-a".to_string(),
                        current_capabilities: vec![
                            "fs.read".to_string(),
                            "network.fetch".to_string(),
                        ],
                        proposed_minimal_capabilities: vec!["fs.read".to_string()],
                        removed_capabilities: vec!["network.fetch".to_string()],
                        capability_justifications: vec![
                            crate::frankentui_adapter::CapabilityJustificationDrillView {
                                capability: "fs.read".to_string(),
                                justification: "static analysis path".to_string(),
                                static_analysis_ref: Some(
                                    "frankentui://proof/static/fs-read".to_string(),
                                ),
                                ablation_result_ref: None,
                                theorem_check_ref: None,
                                operator_attestation_ref: None,
                                inherited_ref: None,
                                playback_ref: "frankentui://proof/static/fs-read".to_string(),
                            },
                        ],
                    }],
                    escrow_event_feed: vec![
                        crate::frankentui_adapter::CapabilityDeltaEscrowEventView {
                            receipt_id: "escrow-1".to_string(),
                            extension_id: "ext-a".to_string(),
                            capability: Some("network.fetch".to_string()),
                            decision_kind: "challenge".to_string(),
                            outcome: "pending".to_string(),
                            trace_id: "trace-escrow-1".to_string(),
                            decision_id: "decision-escrow-1".to_string(),
                            policy_id: "policy-a".to_string(),
                            error_code: None,
                            timestamp_ns: 1_700_000_000_421_000_000,
                            receipt_ref: "frankentui://escrow-receipt/escrow-1".to_string(),
                            replay_ref: "frankentui://replay/escrow/escrow-1".to_string(),
                        },
                    ],
                    override_rationale_rows: vec![OverrideRationaleView {
                        override_id: "override-1".to_string(),
                        extension_id: "ext-a".to_string(),
                        capability: Some("network.fetch".to_string()),
                        rationale: "manual override".to_string(),
                        signed_justification_ref: "frankentui://signed-override/override-1"
                            .to_string(),
                        review_status: OverrideReviewStatus::Pending,
                        grant_expiry_status: GrantExpiryStatus::ExpiringSoon,
                        requested_at_unix_ms: 1_700_000_000_422,
                        reviewed_at_unix_ms: None,
                        expires_at_unix_ms: Some(1_700_000_001_422),
                        receipt_ref: "frankentui://escrow-receipt/escrow-1".to_string(),
                        replay_ref: "frankentui://replay/escrow/escrow-1".to_string(),
                    }],
                    ..Default::default()
                },
            ),
        );
        let proof_lineage = FrankentuiViewPayload::ProofSpecializationLineageDashboard(
            ProofSpecializationLineageDashboardView::from_partial(
                ProofSpecializationLineagePartial {
                    cluster: "prod".to_string(),
                    zone: "us-east".to_string(),
                    security_epoch: Some(8),
                    generated_at_unix_ms: Some(1_700_000_000_444),
                    proof_inventory: vec![ProofInventoryRowView {
                        proof_id: "proof-cap-1".to_string(),
                        proof_kind: ProofInventoryKind::CapabilityWitness,
                        validity_status: ProofValidityStatus::Valid,
                        epoch_id: 8,
                        linked_specialization_count: 2,
                        enabled_specialization_ids: vec![
                            "spec-a".to_string(),
                            "spec-b".to_string(),
                        ],
                        proof_ref: "frankentui://proof/proof-cap-1".to_string(),
                    }],
                    active_specializations: vec![ActiveSpecializationRowView {
                        specialization_id: "spec-a".to_string(),
                        target_id: "ext-a".to_string(),
                        target_kind: "extension".to_string(),
                        optimization_class: "ifc_check_elision".to_string(),
                        latency_reduction_millionths: 200_000,
                        throughput_increase_millionths: 300_000,
                        proof_input_ids: vec!["proof-cap-1".to_string()],
                        transformation_ref: "frankentui://transform/spec-a".to_string(),
                        receipt_ref: "frankentui://receipt/spec-a".to_string(),
                        activated_at_unix_ms: 1_700_000_000_430,
                    }],
                    invalidation_feed: vec![SpecializationInvalidationRowView {
                        invalidation_id: "inv-1".to_string(),
                        specialization_id: "spec-a".to_string(),
                        target_id: "ext-a".to_string(),
                        reason: ProofSpecializationInvalidationReason::ProofExpired,
                        reason_detail: "window elapsed".to_string(),
                        proof_id: Some("proof-cap-1".to_string()),
                        old_epoch_id: Some(7),
                        new_epoch_id: Some(8),
                        fallback_confirmed: true,
                        fallback_confirmation_ref: "frankentui://fallback/spec-a".to_string(),
                        occurred_at_unix_ms: 1_700_000_000_431,
                    }],
                    fallback_events: vec![SpecializationFallbackEventView {
                        event_id: "fb-1".to_string(),
                        specialization_id: Some("spec-a".to_string()),
                        target_id: "ext-a".to_string(),
                        reason: SpecializationFallbackReason::ProofExpired,
                        reason_detail: "fallback activated".to_string(),
                        unspecialized_path_ref: "frankentui://path/ext-a/unspecialized".to_string(),
                        compilation_ref: "frankentui://compile/ext-a".to_string(),
                        occurred_at_unix_ms: 1_700_000_000_432,
                    }],
                    bulk_invalidation_alert_threshold: Some(1),
                    degraded_coverage_alert_threshold_millionths: Some(900_000),
                    ..Default::default()
                },
            ),
        );

        for payload in [
            replay,
            policy,
            dashboard,
            replacement,
            invariants,
            flow,
            capability_delta,
            proof_lineage,
        ] {
            let envelope = AdapterEnvelope::new(
                "trace-variants",
                1_700_000_000_000,
                AdapterStream::ControlDashboard,
                UpdateKind::Snapshot,
                payload,
            );
            let json = serde_json::to_value(&envelope).expect("serialize");
            assert!(json["payload"].is_object(), "payload must be an object");
        }
    }

    #[test]
    fn frankentui_replay_status_enum_values_stable() {
        let statuses = [
            ReplayStatus::Running,
            ReplayStatus::Complete,
            ReplayStatus::Failed,
            ReplayStatus::NoEvents,
        ];
        let expected = ["running", "complete", "failed", "no_events"];
        for (status, expected_str) in statuses.iter().zip(expected.iter()) {
            let json = serde_json::to_value(status).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn frankentui_stream_enum_values_stable() {
        let streams = [
            AdapterStream::IncidentReplay,
            AdapterStream::PolicyExplanation,
            AdapterStream::ControlDashboard,
            AdapterStream::ControlPlaneInvariantsDashboard,
            AdapterStream::FlowDecisionDashboard,
            AdapterStream::CapabilityDeltaDashboard,
            AdapterStream::ReplacementProgressDashboard,
            AdapterStream::ProofSpecializationLineageDashboard,
        ];
        let expected = [
            "incident_replay",
            "policy_explanation",
            "control_dashboard",
            "control_plane_invariants_dashboard",
            "flow_decision_dashboard",
            "capability_delta_dashboard",
            "replacement_progress_dashboard",
            "proof_specialization_lineage_dashboard",
        ];
        for (stream, expected_str) in streams.iter().zip(expected.iter()) {
            let json = serde_json::to_value(stream).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn frankentui_update_kind_enum_values_stable() {
        let kinds = [
            UpdateKind::Snapshot,
            UpdateKind::Delta,
            UpdateKind::Heartbeat,
        ];
        let expected = ["snapshot", "delta", "heartbeat"];
        for (kind, expected_str) in kinds.iter().zip(expected.iter()) {
            let json = serde_json::to_value(kind).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    // ── frankensqlite boundary ─────────────────────────────────────────

    fn sample_store_record() -> StoreRecord {
        let mut metadata = BTreeMap::new();
        metadata.insert("kind".to_string(), "benchmark".to_string());
        StoreRecord {
            store: StoreKind::BenchmarkLedger,
            key: "bench/latency".to_string(),
            value: vec![42, 0, 0, 0],
            metadata,
            revision: 1,
        }
    }

    #[test]
    fn frankensqlite_store_record_schema_compliance() {
        let contract = frankensqlite_store_record_contract();
        let record = sample_store_record();
        let violations = verify_schema_compliance(&record, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_store_record_deterministic_serde() {
        let record = sample_store_record();
        verify_deterministic_serde(&record).expect("must be deterministic");
    }

    #[test]
    fn frankensqlite_store_kind_integration_points_unique() {
        let kinds = [
            StoreKind::ReplayIndex,
            StoreKind::EvidenceIndex,
            StoreKind::BenchmarkLedger,
            StoreKind::PolicyCache,
            StoreKind::PlasWitness,
            StoreKind::ReplacementLineage,
            StoreKind::IfcProvenance,
            StoreKind::SpecializationIndex,
        ];

        let mut seen_names = BTreeSet::new();
        let mut seen_integration = BTreeSet::new();
        for kind in &kinds {
            assert!(
                seen_names.insert(kind.as_str()),
                "duplicate store name: {}",
                kind.as_str()
            );
            assert!(
                seen_integration.insert(kind.integration_point()),
                "duplicate integration point: {}",
                kind.integration_point()
            );
        }
    }

    #[test]
    fn frankensqlite_store_kind_serialization_stable() {
        let kinds = [
            (StoreKind::ReplayIndex, "ReplayIndex"),
            (StoreKind::EvidenceIndex, "EvidenceIndex"),
            (StoreKind::BenchmarkLedger, "BenchmarkLedger"),
            (StoreKind::PolicyCache, "PolicyCache"),
            (StoreKind::PlasWitness, "PlasWitness"),
            (StoreKind::ReplacementLineage, "ReplacementLineage"),
            (StoreKind::IfcProvenance, "IfcProvenance"),
            (StoreKind::SpecializationIndex, "SpecializationIndex"),
        ];
        for (kind, expected_json) in &kinds {
            let json = serde_json::to_value(kind).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_json);
        }
    }

    #[test]
    fn frankensqlite_migration_receipt_schema_compliance() {
        let contract = frankensqlite_migration_receipt_contract();
        let receipt = MigrationReceipt {
            backend: "in_memory".to_string(),
            from_version: 1,
            to_version: 2,
            stores_touched: vec![StoreKind::ReplayIndex],
            records_touched: 5,
            state_hash_before: "abc123".to_string(),
            state_hash_after: "def456".to_string(),
        };
        let violations = verify_schema_compliance(&receipt, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_storage_event_schema_compliance() {
        let contract = frankensqlite_storage_event_contract();
        let event = StorageEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            component: "storage_adapter".to_string(),
            event: "put".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let violations = verify_schema_compliance(&event, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_storage_event_structured_log_compliance() {
        let event = StorageEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            component: "storage_adapter".to_string(),
            event: "put".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_value(&event).expect("serialize");
        let violations = verify_structured_log(&json, "frankensqlite");
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn frankensqlite_error_codes_have_stable_prefix() {
        let errors = [
            StorageError::InvalidContext {
                field: "trace_id".to_string(),
            },
            StorageError::InvalidKey {
                key: "bad".to_string(),
            },
            StorageError::InvalidQuery {
                detail: "bad".to_string(),
            },
            StorageError::NotFound {
                store: StoreKind::ReplayIndex,
                key: "missing".to_string(),
            },
            StorageError::SchemaVersionMismatch {
                expected: 1,
                actual: 2,
            },
            StorageError::MigrationFailed {
                from: 1,
                to: 0,
                reason: "downgrade".to_string(),
            },
            StorageError::IntegrityViolation {
                store: StoreKind::PolicyCache,
                detail: "corrupt".to_string(),
            },
            StorageError::BackendUnavailable {
                backend: "sqlite".to_string(),
                detail: "down".to_string(),
            },
            StorageError::WriteRejected {
                detail: "readonly".to_string(),
            },
        ];
        for err in &errors {
            assert!(
                verify_error_code_format(err.code(), "FE-STOR-"),
                "error code `{}` does not start with FE-STOR-",
                err.code()
            );
        }
    }

    #[test]
    fn frankensqlite_adapter_operations_emit_events() {
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = EventContext::new("trace-contract", "decision-contract", "policy-contract")
            .expect("ctx");

        adapter
            .put(
                StoreKind::ReplayIndex,
                "key-1".to_string(),
                vec![1],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
        adapter
            .get(StoreKind::ReplayIndex, "key-1", &ctx)
            .expect("get");

        let events = StorageAdapter::events(&adapter);
        assert!(events.len() >= 2, "expected at least 2 events");
        for event in events {
            assert_eq!(event.trace_id, "trace-contract");
            assert_eq!(event.component, "storage_adapter");
        }
    }

    #[test]
    fn frankensqlite_query_ordering_is_deterministic() {
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = EventContext::new("trace-order", "decision-order", "policy-order").expect("ctx");

        for key in ["z-key", "a-key", "m-key"] {
            adapter
                .put(
                    StoreKind::EvidenceIndex,
                    key.to_string(),
                    vec![1],
                    BTreeMap::new(),
                    &ctx,
                )
                .expect("put");
        }

        let first_query = adapter
            .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
            .expect("query 1");
        let second_query = adapter
            .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
            .expect("query 2");

        let keys_first: Vec<&str> = first_query.iter().map(|r| r.key.as_str()).collect();
        let keys_second: Vec<&str> = second_query.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys_first, keys_second,
            "query ordering must be deterministic"
        );
        assert_eq!(keys_first, vec!["a-key", "m-key", "z-key"]);
    }

    // ── fastapi_rust / service endpoint boundary ───────────────────────

    fn sample_health_response() -> EndpointResponse<HealthStatusResponse> {
        EndpointResponse {
            status: "ok".to_string(),
            endpoint: "health".to_string(),
            trace_id: "trace-contract".to_string(),
            request_id: "req-contract".to_string(),
            data: Some(HealthStatusResponse {
                runtime_status: "healthy".to_string(),
                loaded_extensions: vec!["ext-a".to_string()],
                security_epoch: 10,
                gc_pressure_basis_points: 50,
            }),
            error: None,
            log: StructuredLogEvent {
                trace_id: "trace-contract".to_string(),
                decision_id: Some("decision-contract".to_string()),
                policy_id: Some("policy-contract".to_string()),
                component: "service.api".to_string(),
                event: "health.read".to_string(),
                outcome: "ok".to_string(),
                error_code: None,
            },
        }
    }

    #[test]
    fn fastapi_endpoint_response_schema_compliance() {
        let contract = fastapi_endpoint_response_contract();
        let response = sample_health_response();
        let violations = verify_schema_compliance(&response, &contract);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn fastapi_endpoint_response_deterministic_serde() {
        let response = sample_health_response();
        verify_deterministic_serde(&response).expect("must be deterministic");
    }

    #[test]
    fn fastapi_endpoint_response_log_structured_compliance() {
        let response = sample_health_response();
        let json = serde_json::to_value(&response).expect("serialize");
        let log_json = &json["log"];
        let violations = verify_structured_log(log_json, "fastapi_rust");
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn fastapi_error_envelope_schema_stable() {
        let error = ErrorEnvelope {
            error_code: "unauthorized".to_string(),
            message: "missing required scope".to_string(),
            trace_id: "trace-1".to_string(),
            component: "service.api".to_string(),
            details: BTreeMap::new(),
        };
        let json = serde_json::to_value(&error).expect("serialize");
        let obj = json.as_object().expect("object");
        for field in ["error_code", "message", "trace_id", "component", "details"] {
            assert!(
                obj.contains_key(field),
                "missing field `{field}` in ErrorEnvelope"
            );
        }
    }

    #[test]
    fn fastapi_control_action_enum_values_stable() {
        let actions = [
            ControlAction::Start,
            ControlAction::Stop,
            ControlAction::Suspend,
            ControlAction::Quarantine,
        ];
        let expected = ["Start", "Stop", "Suspend", "Quarantine"];
        for (action, expected_str) in actions.iter().zip(expected.iter()) {
            let json = serde_json::to_value(action).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn fastapi_replay_command_enum_values_stable() {
        let commands = [
            ReplayCommand::Start,
            ReplayCommand::Stop,
            ReplayCommand::Status,
        ];
        let expected = ["Start", "Stop", "Status"];
        for (cmd, expected_str) in commands.iter().zip(expected.iter()) {
            let json = serde_json::to_value(cmd).expect("serialize");
            assert_eq!(json.as_str().unwrap(), *expected_str);
        }
    }

    #[test]
    fn fastapi_scope_constants_are_non_empty() {
        for scope in [
            SCOPE_HEALTH_READ,
            SCOPE_CONTROL_WRITE,
            SCOPE_EVIDENCE_READ,
            SCOPE_REPLAY_READ,
            SCOPE_REPLAY_WRITE,
        ] {
            assert!(!scope.is_empty(), "scope constant must not be empty");
            assert!(
                scope.starts_with("engine."),
                "scope `{scope}` must start with 'engine.'"
            );
        }
    }

    #[test]
    fn fastapi_request_context_serde_round_trip() {
        let ctx = RequestContext {
            trace_id: "trace-1".to_string(),
            request_id: "req-1".to_string(),
            component: "service.api".to_string(),
            decision_id: Some("d-1".to_string()),
            policy_id: None,
        };
        verify_deterministic_serde(&ctx).expect("must be deterministic");
    }

    #[test]
    fn fastapi_auth_context_serde_round_trip() {
        let auth = AuthContext {
            subject: "operator@example".to_string(),
            scopes: vec!["engine.health.read".to_string()],
        };
        verify_deterministic_serde(&auth).expect("must be deterministic");
    }

    // ── cross-boundary / meta tests ────────────────────────────────────

    #[test]
    fn version_compatibility_registry_covers_all_boundaries() {
        let registry = version_compatibility_registry();
        let boundaries: BTreeSet<String> = registry
            .iter()
            .map(|entry| entry.boundary.clone())
            .collect();
        assert!(boundaries.contains("frankentui"));
        assert!(boundaries.contains("frankensqlite"));
        assert!(boundaries.contains("fastapi_rust"));

        for entry in &registry {
            assert!(
                entry.current_version >= entry.minimum_compatible_version,
                "boundary {}: current {} < minimum {}",
                entry.boundary,
                entry.current_version,
                entry.minimum_compatible_version
            );
        }
    }

    #[test]
    fn integration_point_inventory_covers_all_boundaries() {
        let inventory = integration_point_inventory();
        assert!(inventory.contains_key("frankentui"));
        assert!(inventory.contains_key("frankensqlite"));
        assert!(inventory.contains_key("fastapi_rust"));

        for (boundary, types) in &inventory {
            assert!(
                !types.is_empty(),
                "boundary {boundary} must have at least one type"
            );
        }
    }

    #[test]
    fn schema_contract_detects_missing_field() {
        let contract = frankensqlite_store_record_contract();
        let mut json = serde_json::json!({
            "store": "ReplayIndex",
            "key": "k1",
            "value": [1],
            "metadata": {}
        });
        // missing "revision"
        let violations = contract.verify(&json);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].regression_class, RegressionClass::Breaking);
        assert!(violations[0].detail.contains("revision"));

        // add it back
        json["revision"] = serde_json::json!(1);
        let violations = contract.verify(&json);
        assert!(violations.is_empty());
    }

    #[test]
    fn schema_contract_detects_wrong_type() {
        let contract = frankensqlite_store_record_contract();
        let json = serde_json::json!({
            "store": "ReplayIndex",
            "key": "k1",
            "value": [1],
            "metadata": {},
            "revision": "not_a_number"
        });
        let violations = contract.verify(&json);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].detail.contains("revision"));
        assert!(violations[0].detail.contains("number"));
    }

    #[test]
    fn regression_class_ordering() {
        assert!(RegressionClass::Breaking < RegressionClass::Behavioral);
        assert!(RegressionClass::Behavioral < RegressionClass::Observability);
        assert!(RegressionClass::Observability < RegressionClass::Performance);
    }

    #[test]
    fn contract_violation_display() {
        let violation = ContractViolation {
            boundary: "frankentui".to_string(),
            contract_name: "AdapterEnvelope".to_string(),
            regression_class: RegressionClass::Breaking,
            detail: "missing field `payload`".to_string(),
        };
        let display = violation.to_string();
        assert!(display.contains("BREAKING"));
        assert!(display.contains("frankentui"));
        assert!(display.contains("AdapterEnvelope"));
        assert!(display.contains("missing field"));
    }

    #[test]
    fn contract_suite_result_serde_round_trip() {
        let result = ContractSuiteResult {
            total_contracts: 5,
            passed: 4,
            failed: 1,
            violations: vec![ContractViolation {
                boundary: "test".to_string(),
                contract_name: "TestType".to_string(),
                regression_class: RegressionClass::Behavioral,
                detail: "test violation".to_string(),
            }],
            boundaries_covered: {
                let mut set = BTreeSet::new();
                set.insert("frankentui".to_string());
                set
            },
        };
        verify_deterministic_serde(&result).expect("must be deterministic");
    }

    #[test]
    fn contract_suite_result_display() {
        let result = ContractSuiteResult {
            total_contracts: 10,
            passed: 8,
            failed: 2,
            violations: Vec::new(),
            boundaries_covered: BTreeSet::new(),
        };
        let display = result.to_string();
        assert!(display.contains("contracts=10"));
        assert!(display.contains("passed=8"));
        assert!(display.contains("failed=2"));
    }

    #[test]
    fn structured_log_verification_detects_missing_fields() {
        let incomplete = serde_json::json!({
            "trace_id": "t1",
            "component": "test"
            // missing "event" and "outcome"
        });
        let violations = verify_structured_log(&incomplete, "test");
        assert_eq!(violations.len(), 2);
        let fields: BTreeSet<String> = violations.iter().map(|v| v.detail.clone()).collect();
        assert!(fields.iter().any(|d| d.contains("event")));
        assert!(fields.iter().any(|d| d.contains("outcome")));
    }

    #[test]
    fn error_code_format_verification() {
        assert!(verify_error_code_format("FE-STOR-0001", "FE-STOR-"));
        assert!(verify_error_code_format("FE-STOR-0009", "FE-STOR-"));
        assert!(!verify_error_code_format("UNKNOWN-001", "FE-STOR-"));
    }

    // ── deterministic cross-boundary data exchange ─────────────────────

    #[test]
    fn cross_boundary_storage_then_tui_deterministic() {
        // Simulate: engine writes to storage, reads back, generates TUI view
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = EventContext::new("trace-xboundary", "decision-xb", "policy-xb").expect("ctx");

        adapter
            .put(
                StoreKind::EvidenceIndex,
                "decision/1".to_string(),
                b"evidence-payload".to_vec(),
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");

        let loaded = adapter
            .get(StoreKind::EvidenceIndex, "decision/1", &ctx)
            .expect("get")
            .expect("record exists");

        // Generate TUI view from loaded data
        let replay_event =
            ReplayEventView::new(1, "storage_adapter", "put", "ok", 1_700_000_000_000);
        let replay =
            IncidentReplayView::snapshot(&loaded.key, "evidence-replay", vec![replay_event]);
        let envelope = AdapterEnvelope::new(
            "trace-xboundary",
            1_700_000_000_000,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            FrankentuiViewPayload::IncidentReplay(replay),
        );

        // Both sides should be deterministic
        verify_deterministic_serde(&loaded).expect("storage record deterministic");
        verify_deterministic_serde(&envelope).expect("tui envelope deterministic");
    }

    #[test]
    fn cross_boundary_service_error_contract_matches_storage_error() {
        // Verify that service endpoint errors and storage errors both carry
        // structured fields suitable for the same telemetry pipeline.
        let storage_event = StorageEvent {
            trace_id: "trace-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "storage_adapter".to_string(),
            event: "put".to_string(),
            outcome: "error".to_string(),
            error_code: Some("FE-STOR-0002".to_string()),
        };

        let service_log = StructuredLogEvent {
            trace_id: "trace-1".to_string(),
            decision_id: Some("d-1".to_string()),
            policy_id: Some("p-1".to_string()),
            component: "service.api".to_string(),
            event: "control.execute".to_string(),
            outcome: "error".to_string(),
            error_code: Some("unauthorized".to_string()),
        };

        // Both should pass structured log verification
        let storage_json = serde_json::to_value(&storage_event).expect("serialize");
        let service_json = serde_json::to_value(&service_log).expect("serialize");

        let v1 = verify_structured_log(&storage_json, "frankensqlite");
        let v2 = verify_structured_log(&service_json, "fastapi_rust");
        assert!(v1.is_empty(), "storage log violations: {v1:?}");
        assert!(v2.is_empty(), "service log violations: {v2:?}");
    }

    #[test]
    fn field_type_matches_correctly() {
        assert!(FieldType::String.matches(&serde_json::json!("hello")));
        assert!(!FieldType::String.matches(&serde_json::json!(42)));
        assert!(FieldType::Number.matches(&serde_json::json!(42)));
        assert!(FieldType::Bool.matches(&serde_json::json!(true)));
        assert!(FieldType::Array.matches(&serde_json::json!([1, 2])));
        assert!(FieldType::Object.matches(&serde_json::json!({"a": 1})));
        assert!(FieldType::Null.matches(&serde_json::json!(null)));
    }

    #[test]
    fn field_type_display() {
        assert_eq!(FieldType::String.to_string(), "string");
        assert_eq!(FieldType::Number.to_string(), "number");
        assert_eq!(FieldType::Bool.to_string(), "bool");
        assert_eq!(FieldType::Array.to_string(), "array");
        assert_eq!(FieldType::Object.to_string(), "object");
        assert_eq!(FieldType::Null.to_string(), "null");
    }

    #[test]
    fn regression_class_display() {
        assert_eq!(RegressionClass::Breaking.to_string(), "BREAKING");
        assert_eq!(RegressionClass::Behavioral.to_string(), "BEHAVIORAL");
        assert_eq!(RegressionClass::Observability.to_string(), "OBSERVABILITY");
        assert_eq!(RegressionClass::Performance.to_string(), "PERFORMANCE");
    }

    #[test]
    fn regression_class_serde_round_trip() {
        for class in [
            RegressionClass::Breaking,
            RegressionClass::Behavioral,
            RegressionClass::Observability,
            RegressionClass::Performance,
        ] {
            verify_deterministic_serde(&class).expect("must be deterministic");
        }
    }

    // -- Enrichment: Display uniqueness, edge cases, serde, error trait --

    #[test]
    fn regression_class_display_all_unique() {
        let displays: BTreeSet<String> = [
            RegressionClass::Breaking,
            RegressionClass::Behavioral,
            RegressionClass::Observability,
            RegressionClass::Performance,
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn field_type_display_all_unique() {
        let displays: BTreeSet<String> = [
            FieldType::String,
            FieldType::Number,
            FieldType::Bool,
            FieldType::Array,
            FieldType::Object,
            FieldType::Null,
        ]
        .iter()
        .map(|f| f.to_string())
        .collect();
        assert_eq!(displays.len(), 6);
    }

    #[test]
    fn contract_violation_display_includes_all_parts() {
        let v = ContractViolation {
            boundary: "tui".to_string(),
            contract_name: "Envelope".to_string(),
            regression_class: RegressionClass::Breaking,
            detail: "missing field".to_string(),
        };
        let display = v.to_string();
        assert!(display.contains("BREAKING"));
        assert!(display.contains("tui"));
        assert!(display.contains("Envelope"));
        assert!(display.contains("missing field"));
    }

    #[test]
    fn contract_violation_serde_roundtrip() {
        let v = ContractViolation {
            boundary: "sqlite".to_string(),
            contract_name: "StoreRecord".to_string(),
            regression_class: RegressionClass::Behavioral,
            detail: "ordering changed".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ContractViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn schema_contract_verify_non_object_returns_breaking() {
        let contract = frankentui_envelope_contract();
        let violations = contract.verify(&serde_json::json!("not an object"));
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].regression_class, RegressionClass::Breaking);
        assert!(violations[0].detail.contains("expected JSON object"));
    }

    #[test]
    fn verify_error_code_format_checks_prefix() {
        assert!(verify_error_code_format("FE-IFC-001", "FE-IFC"));
        assert!(!verify_error_code_format("FE-IFC-001", "FE-SAFE"));
        assert!(!verify_error_code_format("", "FE-"));
    }

    #[test]
    fn verify_structured_log_missing_fields() {
        let log_json = serde_json::json!({"trace_id": "t1"});
        let violations = verify_structured_log(&log_json, "test");
        // Should report missing component, event, outcome
        assert!(violations.len() >= 3);
        assert!(
            violations
                .iter()
                .all(|v| v.regression_class == RegressionClass::Observability)
        );
    }

    #[test]
    fn schema_contract_serde_roundtrip() {
        let contract = frankentui_envelope_contract();
        let json = serde_json::to_string(&contract).unwrap();
        let back: SchemaContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract, back);
    }

    // ── Enrichment: serde roundtrip tests ────────────────────────────

    #[test]
    fn version_compatibility_entry_serde_roundtrip() {
        let entry = VersionCompatibilityEntry {
            boundary: "parser-ast".to_string(),
            current_version: 3,
            minimum_compatible_version: 1,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: VersionCompatibilityEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
    }

    #[test]
    fn field_type_serde_roundtrip_all_variants() {
        let all = [
            FieldType::String,
            FieldType::Number,
            FieldType::Bool,
            FieldType::Array,
            FieldType::Object,
            FieldType::Null,
        ];
        for ft in &all {
            let json = serde_json::to_string(ft).unwrap();
            let back: FieldType = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, ft);
        }
    }

    #[test]
    fn schema_contract_verify_empty_required_fields() {
        let contract = SchemaContract {
            boundary: "test-empty".to_string(),
            type_name: "EmptySchema".to_string(),
            required_fields: BTreeSet::new(),
            field_types: BTreeMap::new(),
        };
        let obj = serde_json::json!({"anything": "goes"});
        let violations = contract.verify(&obj);
        assert!(
            violations.is_empty(),
            "empty required_fields means no violations"
        );
    }

    // ── enrichment: clone equality ──────────────────────────────────────

    #[test]
    fn enrichment_clone_eq_regression_class() {
        let a = RegressionClass::Performance;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_contract_violation() {
        let a = ContractViolation {
            boundary: "frankentui".to_string(),
            contract_name: "AdapterEnvelope".to_string(),
            regression_class: RegressionClass::Observability,
            detail: "missing field `trace_id`".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_schema_contract() {
        let a = frankensqlite_migration_receipt_contract();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_field_type() {
        let a = FieldType::Array;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_contract_suite_result() {
        let a = ContractSuiteResult {
            total_contracts: 7,
            passed: 5,
            failed: 2,
            violations: vec![ContractViolation {
                boundary: "frankensqlite".to_string(),
                contract_name: "StoreRecord".to_string(),
                regression_class: RegressionClass::Breaking,
                detail: "missing field `revision`".to_string(),
            }],
            boundaries_covered: {
                let mut s = BTreeSet::new();
                s.insert("frankensqlite".to_string());
                s
            },
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── enrichment: JSON field presence ─────────────────────────────────

    #[test]
    fn enrichment_json_field_presence_contract_violation() {
        let v = ContractViolation {
            boundary: "tui".to_string(),
            contract_name: "TestType".to_string(),
            regression_class: RegressionClass::Performance,
            detail: "latency exceeded".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"boundary\""));
        assert!(json.contains("\"contract_name\""));
        assert!(json.contains("\"regression_class\""));
        assert!(json.contains("\"detail\""));
    }

    #[test]
    fn enrichment_json_field_presence_version_compatibility_entry() {
        let entry = VersionCompatibilityEntry {
            boundary: "fastapi_rust".to_string(),
            current_version: 2,
            minimum_compatible_version: 1,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"boundary\""));
        assert!(json.contains("\"current_version\""));
        assert!(json.contains("\"minimum_compatible_version\""));
    }

    #[test]
    fn enrichment_json_field_presence_contract_suite_result() {
        let result = ContractSuiteResult {
            total_contracts: 3,
            passed: 2,
            failed: 1,
            violations: Vec::new(),
            boundaries_covered: BTreeSet::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"total_contracts\""));
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"failed\""));
        assert!(json.contains("\"violations\""));
        assert!(json.contains("\"boundaries_covered\""));
    }

    // ── enrichment: display uniqueness ──────────────────────────────────

    #[test]
    fn enrichment_display_uniqueness_contract_suite_result() {
        let results: Vec<ContractSuiteResult> = (0..4)
            .map(|i| ContractSuiteResult {
                total_contracts: 10 + i,
                passed: 8 + i,
                failed: 2,
                violations: Vec::new(),
                boundaries_covered: BTreeSet::new(),
            })
            .collect();
        let displays: BTreeSet<String> = results.iter().map(|r| r.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    // ── enrichment: boundary condition ───────────────────────────────────

    #[test]
    fn enrichment_boundary_contract_suite_all_passing_zero_violations() {
        let result = ContractSuiteResult {
            total_contracts: 0,
            passed: 0,
            failed: 0,
            violations: Vec::new(),
            boundaries_covered: BTreeSet::new(),
        };
        assert!(result.is_passing());
        // Display should still produce valid output for zero counters.
        let display = result.to_string();
        assert!(display.contains("contracts=0"));
        assert!(display.contains("passed=0"));
        assert!(display.contains("failed=0"));
        assert!(display.contains("boundaries=0"));
    }

    // ── enrichment: Ord determinism ─────────────────────────────────────

    #[test]
    fn enrichment_field_type_ord_determinism() {
        let mut a = vec![
            FieldType::Null,
            FieldType::Object,
            FieldType::String,
            FieldType::Bool,
            FieldType::Number,
            FieldType::Array,
        ];
        let mut b = a.clone();
        b.reverse();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    // ── enrichment: Copy semantics ──────────────────────────────────────

    #[test]
    fn enrichment_regression_class_copy_semantics() {
        let a = RegressionClass::Breaking;
        let b = a; // Copy
        let c = a; // still valid after copy
        assert_eq!(b, c);
        assert_eq!(a, RegressionClass::Breaking);
    }

    #[test]
    fn enrichment_field_type_copy_semantics() {
        let a = FieldType::Object;
        let b = a; // Copy
        let c = a; // still valid after copy
        assert_eq!(b, c);
        assert_eq!(a, FieldType::Object);
    }

    // ── enrichment: BTreeSet deduplication via Ord ──────────────────────

    #[test]
    fn enrichment_regression_class_btreeset_dedup() {
        let mut set = BTreeSet::new();
        set.insert(RegressionClass::Breaking);
        set.insert(RegressionClass::Breaking);
        set.insert(RegressionClass::Behavioral);
        set.insert(RegressionClass::Behavioral);
        set.insert(RegressionClass::Observability);
        set.insert(RegressionClass::Performance);
        assert_eq!(
            set.len(),
            4,
            "BTreeSet should deduplicate identical variants"
        );
    }

    #[test]
    fn enrichment_field_type_btreeset_dedup() {
        let mut set = BTreeSet::new();
        set.insert(FieldType::String);
        set.insert(FieldType::String);
        set.insert(FieldType::Number);
        set.insert(FieldType::Number);
        set.insert(FieldType::Bool);
        set.insert(FieldType::Array);
        set.insert(FieldType::Object);
        set.insert(FieldType::Null);
        assert_eq!(
            set.len(),
            6,
            "BTreeSet should deduplicate identical FieldType variants"
        );
    }

    // ── enrichment: Display exact format ────────────────────────────────

    #[test]
    fn enrichment_contract_violation_display_exact_format() {
        let v = ContractViolation {
            boundary: "mybound".to_string(),
            contract_name: "MyType".to_string(),
            regression_class: RegressionClass::Performance,
            detail: "latency 200ms > 100ms".to_string(),
        };
        assert_eq!(
            v.to_string(),
            "[PERFORMANCE] mybound/MyType: latency 200ms > 100ms"
        );
    }

    #[test]
    fn enrichment_contract_suite_result_display_exact_format() {
        let r = ContractSuiteResult {
            total_contracts: 15,
            passed: 12,
            failed: 3,
            violations: Vec::new(),
            boundaries_covered: {
                let mut s = BTreeSet::new();
                s.insert("a".to_string());
                s.insert("b".to_string());
                s
            },
        };
        assert_eq!(
            r.to_string(),
            "contracts=15 passed=12 failed=3 boundaries=2"
        );
    }

    // ── enrichment: SchemaContract JSON field presence ──────────────────

    #[test]
    fn enrichment_json_field_presence_schema_contract() {
        let contract = SchemaContract {
            boundary: "test".to_string(),
            type_name: "TestType".to_string(),
            required_fields: {
                let mut s = BTreeSet::new();
                s.insert("alpha".to_string());
                s
            },
            field_types: {
                let mut m = BTreeMap::new();
                m.insert("alpha".to_string(), FieldType::String);
                m
            },
        };
        let json = serde_json::to_string(&contract).unwrap();
        assert!(json.contains("\"boundary\""));
        assert!(json.contains("\"type_name\""));
        assert!(json.contains("\"required_fields\""));
        assert!(json.contains("\"field_types\""));
    }

    // ── enrichment: verify edge cases ──────────────────────────────────

    #[test]
    fn enrichment_schema_contract_verify_null_field_skips_type_check() {
        // When a field is present but null, the let-chain `!value.is_null()`
        // should skip the type mismatch check.
        let mut types = BTreeMap::new();
        types.insert("optional_field".to_string(), FieldType::Number);
        let contract = SchemaContract {
            boundary: "test".to_string(),
            type_name: "NullCheck".to_string(),
            required_fields: BTreeSet::new(),
            field_types: types,
        };
        let json = serde_json::json!({"optional_field": null});
        let violations = contract.verify(&json);
        assert!(
            violations.is_empty(),
            "null field should not trigger type mismatch"
        );
    }

    #[test]
    fn enrichment_schema_contract_verify_multiple_missing_fields() {
        let contract = frankentui_envelope_contract();
        // Empty object => all 6 required fields missing
        let json = serde_json::json!({});
        let violations = contract.verify(&json);
        assert_eq!(
            violations.len(),
            6,
            "should report all 6 missing required fields"
        );
        for v in &violations {
            assert_eq!(v.regression_class, RegressionClass::Breaking);
            assert!(v.detail.starts_with("missing required field"));
        }
    }

    #[test]
    fn enrichment_schema_contract_verify_extra_fields_no_violation() {
        let contract = frankensqlite_store_record_contract();
        let json = serde_json::json!({
            "store": "ReplayIndex",
            "key": "k1",
            "value": [1],
            "metadata": {},
            "revision": 1,
            "extra_field": "should not cause a violation"
        });
        let violations = contract.verify(&json);
        assert!(
            violations.is_empty(),
            "extra fields should not cause violations"
        );
    }

    // ── enrichment: verify_structured_log non-object ────────────────────

    #[test]
    fn enrichment_verify_structured_log_non_object_input() {
        let violations = verify_structured_log(&serde_json::json!(42), "test_boundary");
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].regression_class,
            RegressionClass::Observability
        );
        assert!(violations[0].detail.contains("must be a JSON object"));
    }

    // ── enrichment: ContractSuiteResult is_passing logic ────────────────

    #[test]
    fn enrichment_contract_suite_result_is_passing_with_violations() {
        let result = ContractSuiteResult {
            total_contracts: 5,
            passed: 4,
            failed: 1,
            violations: vec![ContractViolation {
                boundary: "b".to_string(),
                contract_name: "T".to_string(),
                regression_class: RegressionClass::Breaking,
                detail: "d".to_string(),
            }],
            boundaries_covered: BTreeSet::new(),
        };
        assert!(
            !result.is_passing(),
            "should not be passing when violations exist"
        );
    }

    // ── enrichment: FieldType negative matches ──────────────────────────

    #[test]
    fn enrichment_field_type_matches_negative_cross_checks() {
        // Each FieldType should NOT match values of other types.
        let pairs: Vec<(FieldType, Value)> = vec![
            (FieldType::String, serde_json::json!(42)),
            (FieldType::Number, serde_json::json!("text")),
            (FieldType::Bool, serde_json::json!([])),
            (FieldType::Array, serde_json::json!({})),
            (FieldType::Object, serde_json::json!(true)),
            (FieldType::Null, serde_json::json!("not null")),
        ];
        for (ft, val) in &pairs {
            assert!(!ft.matches(val), "{ft} should not match {val}");
        }
    }

    // ── enrichment: RegressionClass Ord sort stability ──────────────────

    #[test]
    fn enrichment_regression_class_ord_sort_stability() {
        let mut a = vec![
            RegressionClass::Performance,
            RegressionClass::Breaking,
            RegressionClass::Observability,
            RegressionClass::Behavioral,
        ];
        let mut b = a.clone();
        b.reverse();
        a.sort();
        b.sort();
        assert_eq!(
            a, b,
            "sort must be deterministic regardless of initial order"
        );
        assert_eq!(a[0], RegressionClass::Breaking);
        assert_eq!(a[3], RegressionClass::Performance);
    }

    // ── enrichment: VersionCompatibilityEntry inequality ────────────────

    #[test]
    fn enrichment_version_compatibility_entry_inequality() {
        let a = VersionCompatibilityEntry {
            boundary: "frankentui".to_string(),
            current_version: 3,
            minimum_compatible_version: 1,
        };
        let b = VersionCompatibilityEntry {
            boundary: "frankentui".to_string(),
            current_version: 4,
            minimum_compatible_version: 2,
        };
        assert_ne!(a, b, "entries with different versions must not be equal");
    }

    // ── enrichment: serde variant names ─────────────────────────────────

    #[test]
    fn enrichment_regression_class_serde_variant_names_stable() {
        let pairs = [
            (RegressionClass::Breaking, "Breaking"),
            (RegressionClass::Behavioral, "Behavioral"),
            (RegressionClass::Observability, "Observability"),
            (RegressionClass::Performance, "Performance"),
        ];
        for (variant, expected_name) in &pairs {
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(json.as_str().unwrap(), *expected_name);
        }
    }

    // ── enrichment: contract builders boundary names ────────────────────

    #[test]
    fn enrichment_contract_builders_return_correct_boundary_names() {
        assert_eq!(frankentui_envelope_contract().boundary, "frankentui");
        assert_eq!(
            frankensqlite_store_record_contract().boundary,
            "frankensqlite"
        );
        assert_eq!(
            fastapi_endpoint_response_contract().boundary,
            "fastapi_rust"
        );
        assert_eq!(
            frankensqlite_storage_event_contract().boundary,
            "frankensqlite"
        );
        assert_eq!(
            frankensqlite_migration_receipt_contract().boundary,
            "frankensqlite"
        );
    }

    // ── enrichment: integration point inventory uniqueness ──────────────

    #[test]
    fn enrichment_integration_point_inventory_types_unique_within_boundary() {
        let inventory = integration_point_inventory();
        for (boundary, types) in &inventory {
            let unique: BTreeSet<&String> = types.iter().collect();
            assert_eq!(
                unique.len(),
                types.len(),
                "boundary {boundary} has duplicate type names"
            );
        }
    }

    // ── enrichment: verify_deterministic_serde contract ─────────────────

    #[test]
    fn enrichment_verify_deterministic_serde_all_core_types() {
        // Verify every module-defined type round-trips deterministically.
        verify_deterministic_serde(&RegressionClass::Observability).unwrap();
        verify_deterministic_serde(&FieldType::Bool).unwrap();
        verify_deterministic_serde(&ContractViolation {
            boundary: "b".to_string(),
            contract_name: "c".to_string(),
            regression_class: RegressionClass::Performance,
            detail: "d".to_string(),
        })
        .unwrap();
        verify_deterministic_serde(&frankentui_envelope_contract()).unwrap();
        verify_deterministic_serde(&VersionCompatibilityEntry {
            boundary: "x".to_string(),
            current_version: 1,
            minimum_compatible_version: 1,
        })
        .unwrap();
    }

    // ── enrichment: verify_schema_compliance serialization failure ──────

    #[test]
    fn enrichment_schema_contract_verify_mixed_type_and_missing_violations() {
        let contract = frankensqlite_store_record_contract();
        // "revision" wrong type AND "metadata" missing
        let json = serde_json::json!({
            "store": "ReplayIndex",
            "key": "k1",
            "value": [1],
            "revision": "bad_type"
        });
        let violations = contract.verify(&json);
        assert!(
            violations.len() >= 2,
            "expect at least missing + type mismatch violations"
        );
        let has_missing = violations
            .iter()
            .any(|v| v.detail.contains("missing required field"));
        let has_type = violations
            .iter()
            .any(|v| v.detail.contains("expected type"));
        assert!(has_missing, "should report missing field");
        assert!(has_type, "should report type mismatch");
    }
}
