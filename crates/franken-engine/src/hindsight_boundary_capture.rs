use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

pub const BEAD_ID: &str = "bd-1lsy.9.11.1";
pub const CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-hindsight-boundary-capture.contract.v1";
pub const BOUNDARY_CATALOG_SCHEMA_VERSION: &str =
    "franken-engine.rgc-hindsight-boundary-catalog.v1";
pub const MINIMAL_REPLAY_INPUT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-minimal-replay-input-schema.v1";
pub const BOUNDARY_REDACTION_MAP_SCHEMA_VERSION: &str =
    "franken-engine.rgc-boundary-redaction-map.v1";
pub const BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-boundary-capture-event.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryClass {
    ClockRead,
    RandomnessDraw,
    FilesystemInput,
    NetworkResponse,
    ModuleResolution,
    SchedulingDecision,
    ControllerOverride,
    ExternalPolicyRead,
    HardwareSurfaceRead,
}

impl BoundaryClass {
    pub const ALL: [Self; 9] = [
        Self::ClockRead,
        Self::RandomnessDraw,
        Self::FilesystemInput,
        Self::NetworkResponse,
        Self::ModuleResolution,
        Self::SchedulingDecision,
        Self::ControllerOverride,
        Self::ExternalPolicyRead,
        Self::HardwareSurfaceRead,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClockRead => "clock_read",
            Self::RandomnessDraw => "randomness_draw",
            Self::FilesystemInput => "filesystem_input",
            Self::NetworkResponse => "network_response",
            Self::ModuleResolution => "module_resolution",
            Self::SchedulingDecision => "scheduling_decision",
            Self::ControllerOverride => "controller_override",
            Self::ExternalPolicyRead => "external_policy_read",
            Self::HardwareSurfaceRead => "hardware_surface_read",
        }
    }
}

impl fmt::Display for BoundaryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClass {
    PublicMetadata,
    PathDigest,
    SecretDigest,
    PolicyDigest,
    HardwareFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionTreatment {
    Plaintext,
    DigestOnly,
    Omit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySufficiency {
    Sufficient,
    NeedsEscalation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldContract {
    pub field: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationCase {
    pub case_id: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldPrivacyMetadata {
    pub field: String,
    pub privacy_class: PrivacyClass,
    pub treatment: RedactionTreatment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryRule {
    pub boundary_class: BoundaryClass,
    pub nondeterminism_tag: String,
    pub minimal_fields: Vec<FieldContract>,
    pub escalation_cases: Vec<EscalationCase>,
    pub redaction_rules: Vec<FieldPrivacyMetadata>,
}

impl BoundaryRule {
    fn required_fields(&self) -> Vec<&str> {
        self.minimal_fields
            .iter()
            .map(|field| field.field.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryCatalog {
    pub schema_version: String,
    pub bead_id: String,
    pub rules: Vec<BoundaryRule>,
}

impl BoundaryCatalog {
    pub fn default_v1() -> Self {
        Self {
            schema_version: BOUNDARY_CATALOG_SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            rules: vec![
                boundary_rule(
                    BoundaryClass::ClockRead,
                    "clock_read",
                    &[
                        ("clock_id", "stable identifier for the clock source"),
                        ("clock_domain", "monotonic or realtime domain label"),
                        ("observed_tick", "captured tick or timestamp value"),
                    ],
                    &[(
                        "clock-non-monotonic",
                        "escalate when the clock source is observed to move backwards or drift unexpectedly",
                    )],
                    &[
                        (
                            "clock_id",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "clock_domain",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "observed_tick",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::RandomnessDraw,
                    "randomness_draw",
                    &[
                        (
                            "generator_id",
                            "stable identifier for the randomness source",
                        ),
                        ("draw_index", "monotonic draw index within the run"),
                        ("sample_digest", "digest of the produced random sample"),
                    ],
                    &[(
                        "randomness-unseeded",
                        "escalate when entropy is sourced outside the declared seeded generator path",
                    )],
                    &[
                        (
                            "generator_id",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "draw_index",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "sample_digest",
                            PrivacyClass::SecretDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::FilesystemInput,
                    "filesystem_input",
                    &[
                        ("operation", "filesystem operation kind"),
                        ("path_digest", "digest of the normalized path"),
                        ("content_digest", "digest of the observed bytes or metadata"),
                    ],
                    &[(
                        "filesystem-path-explanation",
                        "escalate when an operator explanation requires the raw path instead of the path digest",
                    )],
                    &[
                        (
                            "operation",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "path_digest",
                            PrivacyClass::PathDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                        (
                            "content_digest",
                            PrivacyClass::SecretDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::NetworkResponse,
                    "network_response",
                    &[
                        (
                            "request_digest",
                            "digest of the normalized request envelope",
                        ),
                        ("response_digest", "digest of the response body or headers"),
                        ("status_code", "HTTP or transport status code"),
                    ],
                    &[(
                        "network-rich-body-needed",
                        "escalate when replay or support requires structured body fields beyond the response digest",
                    )],
                    &[
                        (
                            "request_digest",
                            PrivacyClass::SecretDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                        (
                            "response_digest",
                            PrivacyClass::SecretDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                        (
                            "status_code",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::ModuleResolution,
                    "module_resolution",
                    &[
                        ("specifier", "requested module specifier"),
                        (
                            "referrer_digest",
                            "digest of the requesting referrer context",
                        ),
                        ("resolved_path_digest", "digest of the resolved target"),
                    ],
                    &[(
                        "module-resolution-fallback",
                        "escalate when resolution depended on ambient filesystem fallback heuristics",
                    )],
                    &[
                        (
                            "specifier",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "referrer_digest",
                            PrivacyClass::PathDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                        (
                            "resolved_path_digest",
                            PrivacyClass::PathDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::SchedulingDecision,
                    "scheduling_decision",
                    &[
                        ("queue_id", "stable queue or lane identifier"),
                        ("task_id", "stable task identifier"),
                        (
                            "ordering_digest",
                            "digest of the ordering witness used for the decision",
                        ),
                    ],
                    &[(
                        "scheduler-work-steal",
                        "escalate when work stealing or contested wake-up ordering requires a richer queue snapshot",
                    )],
                    &[
                        (
                            "queue_id",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "task_id",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "ordering_digest",
                            PrivacyClass::SecretDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::ControllerOverride,
                    "controller_override",
                    &[
                        ("controller_id", "stable controller identifier"),
                        ("override_kind", "kind of override or forced route"),
                        ("value_digest", "digest of the override payload"),
                    ],
                    &[(
                        "interactive-controller-input",
                        "escalate when the override was sourced from interactive operator input",
                    )],
                    &[
                        (
                            "controller_id",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "override_kind",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "value_digest",
                            PrivacyClass::SecretDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::ExternalPolicyRead,
                    "external_policy_read",
                    &[
                        ("policy_name", "logical name of the policy surface"),
                        ("policy_digest", "digest of the policy snapshot"),
                        ("policy_epoch", "epoch or monotonic policy version"),
                    ],
                    &[(
                        "unsigned-policy-snapshot",
                        "escalate when the policy snapshot lacks a stable signed digest",
                    )],
                    &[
                        (
                            "policy_name",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "policy_digest",
                            PrivacyClass::PolicyDigest,
                            RedactionTreatment::DigestOnly,
                        ),
                        (
                            "policy_epoch",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                    ],
                ),
                boundary_rule(
                    BoundaryClass::HardwareSurfaceRead,
                    "hardware_surface_read",
                    &[
                        ("surface_kind", "hardware surface or device class"),
                        ("measurement_digest", "digest of the observed measurement"),
                        (
                            "driver_fingerprint",
                            "stable digest of the driver or firmware surface",
                        ),
                    ],
                    &[(
                        "hardware-quote-required",
                        "escalate when later validation requires the raw quote or vendor payload",
                    )],
                    &[
                        (
                            "surface_kind",
                            PrivacyClass::PublicMetadata,
                            RedactionTreatment::Plaintext,
                        ),
                        (
                            "measurement_digest",
                            PrivacyClass::HardwareFingerprint,
                            RedactionTreatment::DigestOnly,
                        ),
                        (
                            "driver_fingerprint",
                            PrivacyClass::HardwareFingerprint,
                            RedactionTreatment::DigestOnly,
                        ),
                    ],
                ),
            ],
        }
    }

    pub fn rule_for(&self, boundary_class: BoundaryClass) -> Option<&BoundaryRule> {
        self.rules
            .iter()
            .find(|rule| rule.boundary_class == boundary_class)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalReplayInputEntry {
    pub boundary_class: BoundaryClass,
    pub required_fields: Vec<String>,
    pub sufficiency_rule: String,
    pub escalation_cases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalReplayInputSchema {
    pub schema_version: String,
    pub bead_id: String,
    pub entries: Vec<MinimalReplayInputEntry>,
}

impl MinimalReplayInputSchema {
    pub fn from_catalog(catalog: &BoundaryCatalog) -> Self {
        let entries = catalog
            .rules
            .iter()
            .map(|rule| MinimalReplayInputEntry {
                boundary_class: rule.boundary_class,
                required_fields: rule
                    .minimal_fields
                    .iter()
                    .map(|field| field.field.clone())
                    .collect(),
                sufficiency_rule:
                    "minimal fields are sufficient unless the capture explicitly marks the event for escalation"
                        .to_string(),
                escalation_cases: rule
                    .escalation_cases
                    .iter()
                    .map(|entry| entry.case_id.clone())
                    .collect(),
            })
            .collect();
        Self {
            schema_version: MINIMAL_REPLAY_INPUT_SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            entries,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryRedactionEntry {
    pub boundary_class: BoundaryClass,
    pub field: String,
    pub privacy_class: PrivacyClass,
    pub treatment: RedactionTreatment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryRedactionMap {
    pub schema_version: String,
    pub bead_id: String,
    pub entries: Vec<BoundaryRedactionEntry>,
}

impl BoundaryRedactionMap {
    pub fn from_catalog(catalog: &BoundaryCatalog) -> Self {
        let entries = catalog
            .rules
            .iter()
            .flat_map(|rule| {
                rule.redaction_rules
                    .iter()
                    .map(|entry| BoundaryRedactionEntry {
                        boundary_class: rule.boundary_class,
                        field: entry.field.clone(),
                        privacy_class: entry.privacy_class,
                        treatment: entry.treatment,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        Self {
            schema_version: BOUNDARY_REDACTION_MAP_SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            entries,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryCaptureContract {
    pub schema_version: String,
    pub bead_id: String,
    pub boundary_catalog: BoundaryCatalog,
    pub minimal_replay_input_schema: MinimalReplayInputSchema,
    pub boundary_redaction_map: BoundaryRedactionMap,
}

impl BoundaryCaptureContract {
    pub fn default_v1() -> Self {
        let boundary_catalog = BoundaryCatalog::default_v1();
        let minimal_replay_input_schema = MinimalReplayInputSchema::from_catalog(&boundary_catalog);
        let boundary_redaction_map = BoundaryRedactionMap::from_catalog(&boundary_catalog);
        Self {
            schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            boundary_catalog,
            minimal_replay_input_schema,
            boundary_redaction_map,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryContext<'a> {
    pub trace_id: &'a str,
    pub decision_id: &'a str,
    pub policy_id: &'a str,
    pub component: &'a str,
    pub virtual_ts: u64,
}

impl<'a> BoundaryContext<'a> {
    pub const fn new(
        trace_id: &'a str,
        decision_id: &'a str,
        policy_id: &'a str,
        component: &'a str,
        virtual_ts: u64,
    ) -> Self {
        Self {
            trace_id,
            decision_id,
            policy_id,
            component,
            virtual_ts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryCaptureRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub boundary_class: BoundaryClass,
    pub virtual_ts: u64,
    pub minimal_fields: BTreeMap<String, String>,
    pub escalation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRedactionValue {
    pub privacy_class: PrivacyClass,
    pub treatment: RedactionTreatment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryCaptureRecord {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub sequence: u64,
    pub boundary_class: BoundaryClass,
    pub nondeterminism_tag: String,
    pub correlation_key: String,
    pub virtual_ts: u64,
    pub minimal_fields: BTreeMap<String, String>,
    pub redaction: BTreeMap<String, FieldRedactionValue>,
    pub sufficiency: ReplaySufficiency,
    pub escalation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalReplayInputRecord {
    pub correlation_key: String,
    pub boundary_class: BoundaryClass,
    pub component: String,
    pub virtual_ts: u64,
    pub minimal_fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalReplayPlan {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inputs: Vec<MinimalReplayInputRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryCaptureLog {
    pub records: Vec<BoundaryCaptureRecord>,
    pub next_sequence: u64,
}

impl BoundaryCaptureLog {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            next_sequence: 0,
        }
    }

    pub fn records(&self) -> &[BoundaryCaptureRecord] {
        &self.records
    }

    pub fn render_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.records.len());
        for record in &self.records {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    pub fn minimal_replay_plans(
        &self,
        catalog: &BoundaryCatalog,
    ) -> Result<Vec<MinimalReplayPlan>, BoundaryCaptureError> {
        let mut grouped =
            BTreeMap::<(String, String, String), Vec<MinimalReplayInputRecord>>::new();
        for record in &self.records {
            let rule = catalog.rule_for(record.boundary_class).ok_or(
                BoundaryCaptureError::MissingBoundaryRule {
                    boundary_class: record.boundary_class,
                },
            )?;
            validate_minimal_fields(rule, record.boundary_class, &record.minimal_fields)?;
            if matches!(record.sufficiency, ReplaySufficiency::NeedsEscalation)
                || record.escalation_reason.is_some()
            {
                return Err(BoundaryCaptureError::ReplayNeedsEscalation {
                    boundary_class: record.boundary_class,
                    correlation_key: record.correlation_key.clone(),
                    reason: record
                        .escalation_reason
                        .clone()
                        .unwrap_or_else(|| "capture marked for escalation".to_string()),
                });
            }
            grouped
                .entry((
                    record.trace_id.clone(),
                    record.decision_id.clone(),
                    record.policy_id.clone(),
                ))
                .or_default()
                .push(MinimalReplayInputRecord {
                    correlation_key: record.correlation_key.clone(),
                    boundary_class: record.boundary_class,
                    component: record.component.clone(),
                    virtual_ts: record.virtual_ts,
                    minimal_fields: record.minimal_fields.clone(),
                });
        }

        Ok(grouped
            .into_iter()
            .map(
                |((trace_id, decision_id, policy_id), inputs)| MinimalReplayPlan {
                    trace_id,
                    decision_id,
                    policy_id,
                    inputs,
                },
            )
            .collect())
    }

    pub fn append(
        &mut self,
        catalog: &BoundaryCatalog,
        request: BoundaryCaptureRequest,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        let BoundaryCaptureRequest {
            trace_id,
            decision_id,
            policy_id,
            component,
            boundary_class,
            virtual_ts,
            minimal_fields,
            escalation_reason,
        } = request;

        let rule = catalog
            .rule_for(boundary_class)
            .ok_or(BoundaryCaptureError::MissingBoundaryRule { boundary_class })?;
        validate_minimal_fields(rule, boundary_class, &minimal_fields)?;

        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let correlation_key = derive_correlation_key(
            boundary_class,
            sequence,
            trace_id.as_str(),
            decision_id.as_str(),
            component.as_str(),
            virtual_ts,
        );
        let sufficiency = if escalation_reason.is_some() {
            ReplaySufficiency::NeedsEscalation
        } else {
            ReplaySufficiency::Sufficient
        };

        let record = BoundaryCaptureRecord {
            schema_version: BOUNDARY_CAPTURE_EVENT_SCHEMA_VERSION.to_string(),
            trace_id,
            decision_id,
            policy_id,
            component,
            sequence,
            boundary_class,
            nondeterminism_tag: rule.nondeterminism_tag.clone(),
            correlation_key,
            virtual_ts,
            minimal_fields,
            redaction: build_redaction_map(rule),
            sufficiency,
            escalation_reason,
        };
        self.records.push(record.clone());
        Ok(record)
    }
}

impl Default for BoundaryCaptureLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryCaptureSession {
    catalog: BoundaryCatalog,
    log: BoundaryCaptureLog,
}

impl BoundaryCaptureSession {
    pub fn new(catalog: BoundaryCatalog) -> Self {
        Self {
            catalog,
            log: BoundaryCaptureLog::new(),
        }
    }

    pub fn default_v1() -> Self {
        Self::new(BoundaryCatalog::default_v1())
    }

    pub fn catalog(&self) -> &BoundaryCatalog {
        &self.catalog
    }

    pub fn log(&self) -> &BoundaryCaptureLog {
        &self.log
    }

    pub fn minimal_replay_plans(&self) -> Result<Vec<MinimalReplayPlan>, BoundaryCaptureError> {
        self.log.minimal_replay_plans(&self.catalog)
    }

    pub fn capture_boundary(
        &mut self,
        request: BoundaryCaptureRequest,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.log.append(&self.catalog, request)
    }

    pub fn capture_clock_read(
        &mut self,
        context: &BoundaryContext<'_>,
        clock_id: &str,
        clock_domain: &str,
        observed_tick: u64,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::ClockRead,
            escalation_reason,
            [
                ("clock_id", clock_id.to_string()),
                ("clock_domain", clock_domain.to_string()),
                ("observed_tick", observed_tick.to_string()),
            ],
        ))
    }

    pub fn capture_randomness_draw(
        &mut self,
        context: &BoundaryContext<'_>,
        generator_id: &str,
        draw_index: u64,
        sample_digest: &str,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::RandomnessDraw,
            escalation_reason,
            [
                ("generator_id", generator_id.to_string()),
                ("draw_index", draw_index.to_string()),
                ("sample_digest", sample_digest.to_string()),
            ],
        ))
    }

    pub fn capture_filesystem_input(
        &mut self,
        context: &BoundaryContext<'_>,
        operation: &str,
        path_digest: &str,
        content_digest: &str,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::FilesystemInput,
            escalation_reason,
            [
                ("operation", operation.to_string()),
                ("path_digest", path_digest.to_string()),
                ("content_digest", content_digest.to_string()),
            ],
        ))
    }

    pub fn capture_network_response(
        &mut self,
        context: &BoundaryContext<'_>,
        request_digest: &str,
        response_digest: &str,
        status_code: u16,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::NetworkResponse,
            escalation_reason,
            [
                ("request_digest", request_digest.to_string()),
                ("response_digest", response_digest.to_string()),
                ("status_code", status_code.to_string()),
            ],
        ))
    }

    pub fn capture_module_resolution(
        &mut self,
        context: &BoundaryContext<'_>,
        specifier: &str,
        referrer_digest: &str,
        resolved_path_digest: &str,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::ModuleResolution,
            escalation_reason,
            [
                ("specifier", specifier.to_string()),
                ("referrer_digest", referrer_digest.to_string()),
                ("resolved_path_digest", resolved_path_digest.to_string()),
            ],
        ))
    }

    pub fn capture_scheduling_decision(
        &mut self,
        context: &BoundaryContext<'_>,
        queue_id: &str,
        task_id: &str,
        ordering_digest: &str,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::SchedulingDecision,
            escalation_reason,
            [
                ("queue_id", queue_id.to_string()),
                ("task_id", task_id.to_string()),
                ("ordering_digest", ordering_digest.to_string()),
            ],
        ))
    }

    pub fn capture_controller_override(
        &mut self,
        context: &BoundaryContext<'_>,
        controller_id: &str,
        override_kind: &str,
        value_digest: &str,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::ControllerOverride,
            escalation_reason,
            [
                ("controller_id", controller_id.to_string()),
                ("override_kind", override_kind.to_string()),
                ("value_digest", value_digest.to_string()),
            ],
        ))
    }

    pub fn capture_external_policy_read(
        &mut self,
        context: &BoundaryContext<'_>,
        policy_name: &str,
        policy_digest: &str,
        policy_epoch: u64,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::ExternalPolicyRead,
            escalation_reason,
            [
                ("policy_name", policy_name.to_string()),
                ("policy_digest", policy_digest.to_string()),
                ("policy_epoch", policy_epoch.to_string()),
            ],
        ))
    }

    pub fn capture_hardware_surface_read(
        &mut self,
        context: &BoundaryContext<'_>,
        surface_kind: &str,
        measurement_digest: &str,
        driver_fingerprint: &str,
        escalation_reason: Option<&str>,
    ) -> Result<BoundaryCaptureRecord, BoundaryCaptureError> {
        self.capture_boundary(build_request(
            context,
            BoundaryClass::HardwareSurfaceRead,
            escalation_reason,
            [
                ("surface_kind", surface_kind.to_string()),
                ("measurement_digest", measurement_digest.to_string()),
                ("driver_fingerprint", driver_fingerprint.to_string()),
            ],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryCaptureError {
    MissingBoundaryRule {
        boundary_class: BoundaryClass,
    },
    MissingRequiredField {
        boundary_class: BoundaryClass,
        field: String,
    },
    UnexpectedField {
        boundary_class: BoundaryClass,
        field: String,
    },
    EmptyField {
        boundary_class: BoundaryClass,
        field: String,
    },
    ReplayNeedsEscalation {
        boundary_class: BoundaryClass,
        correlation_key: String,
        reason: String,
    },
}

impl fmt::Display for BoundaryCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBoundaryRule { boundary_class } => {
                write!(f, "missing boundary rule for {boundary_class}")
            }
            Self::MissingRequiredField {
                boundary_class,
                field,
            } => {
                write!(
                    f,
                    "missing required field `{field}` for boundary class {boundary_class}"
                )
            }
            Self::UnexpectedField {
                boundary_class,
                field,
            } => {
                write!(
                    f,
                    "unexpected minimal field `{field}` for boundary class {boundary_class}"
                )
            }
            Self::EmptyField {
                boundary_class,
                field,
            } => {
                write!(
                    f,
                    "empty field `{field}` for boundary class {boundary_class}"
                )
            }
            Self::ReplayNeedsEscalation {
                boundary_class,
                correlation_key,
                reason,
            } => write!(
                f,
                "boundary class {boundary_class} requires escalation before replay ({correlation_key}): {reason}"
            ),
        }
    }
}

impl std::error::Error for BoundaryCaptureError {}

fn boundary_rule(
    boundary_class: BoundaryClass,
    nondeterminism_tag: &str,
    minimal_fields: &[(&str, &str)],
    escalation_cases: &[(&str, &str)],
    redaction_rules: &[(&str, PrivacyClass, RedactionTreatment)],
) -> BoundaryRule {
    BoundaryRule {
        boundary_class,
        nondeterminism_tag: nondeterminism_tag.to_string(),
        minimal_fields: minimal_fields
            .iter()
            .map(|(field, description)| FieldContract {
                field: (*field).to_string(),
                description: (*description).to_string(),
            })
            .collect(),
        escalation_cases: escalation_cases
            .iter()
            .map(|(case_id, description)| EscalationCase {
                case_id: (*case_id).to_string(),
                description: (*description).to_string(),
            })
            .collect(),
        redaction_rules: redaction_rules
            .iter()
            .map(|(field, privacy_class, treatment)| FieldPrivacyMetadata {
                field: (*field).to_string(),
                privacy_class: *privacy_class,
                treatment: *treatment,
            })
            .collect(),
    }
}

fn build_redaction_map(rule: &BoundaryRule) -> BTreeMap<String, FieldRedactionValue> {
    rule.redaction_rules
        .iter()
        .map(|entry| {
            (
                entry.field.clone(),
                FieldRedactionValue {
                    privacy_class: entry.privacy_class,
                    treatment: entry.treatment,
                },
            )
        })
        .collect()
}

fn validate_minimal_fields(
    rule: &BoundaryRule,
    boundary_class: BoundaryClass,
    minimal_fields: &BTreeMap<String, String>,
) -> Result<(), BoundaryCaptureError> {
    let required_fields = rule.required_fields();

    for required_field in &required_fields {
        let value = minimal_fields.get(*required_field).ok_or_else(|| {
            BoundaryCaptureError::MissingRequiredField {
                boundary_class,
                field: (*required_field).to_string(),
            }
        })?;
        if value.trim().is_empty() {
            return Err(BoundaryCaptureError::EmptyField {
                boundary_class,
                field: (*required_field).to_string(),
            });
        }
    }

    for field in minimal_fields.keys() {
        if !required_fields.contains(&field.as_str()) {
            return Err(BoundaryCaptureError::UnexpectedField {
                boundary_class,
                field: field.clone(),
            });
        }
    }

    Ok(())
}

fn build_request<const N: usize>(
    context: &BoundaryContext<'_>,
    boundary_class: BoundaryClass,
    escalation_reason: Option<&str>,
    fields: [(&str, String); N],
) -> BoundaryCaptureRequest {
    BoundaryCaptureRequest {
        trace_id: context.trace_id.to_string(),
        decision_id: context.decision_id.to_string(),
        policy_id: context.policy_id.to_string(),
        component: context.component.to_string(),
        boundary_class,
        virtual_ts: context.virtual_ts,
        minimal_fields: fields
            .into_iter()
            .map(|(field, value)| (field.to_string(), value))
            .collect(),
        escalation_reason: escalation_reason.map(ToOwned::to_owned),
    }
}

fn derive_correlation_key(
    boundary_class: BoundaryClass,
    sequence: u64,
    trace_id: &str,
    decision_id: &str,
    component: &str,
    virtual_ts: u64,
) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}",
        boundary_class.as_str(),
        sequence,
        trace_id,
        decision_id,
        component,
        virtual_ts
    );
    format!(
        "bcorr_{}",
        ContentHash::compute(canonical.as_bytes()).to_hex()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hindsight_boundary_contract_covers_every_boundary_class() {
        let contract = BoundaryCaptureContract::default_v1();
        let actual: Vec<_> = contract
            .boundary_catalog
            .rules
            .iter()
            .map(|rule| rule.boundary_class)
            .collect();
        assert_eq!(actual, BoundaryClass::ALL);
    }

    #[test]
    fn capture_clock_read_requires_all_fields() {
        let mut session = BoundaryCaptureSession::default_v1();
        let context = BoundaryContext::new("trace-a", "decision-a", "policy-a", "clock", 10);
        let mut request = build_request(
            &context,
            BoundaryClass::ClockRead,
            None,
            [
                ("clock_id", "mono".to_string()),
                ("clock_domain", "monotonic".to_string()),
                ("observed_tick", "10".to_string()),
            ],
        );
        request.minimal_fields.remove("clock_id");
        let error = session
            .capture_boundary(request)
            .expect_err("missing field");
        assert_eq!(
            error,
            BoundaryCaptureError::MissingRequiredField {
                boundary_class: BoundaryClass::ClockRead,
                field: "clock_id".to_string(),
            }
        );
    }

    #[test]
    fn every_boundary_wrapper_emits_expected_class_and_fields() {
        let mut session = BoundaryCaptureSession::default_v1();

        let captures = [
            (
                session
                    .capture_clock_read(
                        &BoundaryContext::new("trace-0", "decision-0", "policy-0", "clock", 1),
                        "mono",
                        "monotonic",
                        1,
                        None,
                    )
                    .expect("clock capture"),
                BoundaryClass::ClockRead,
                ["clock_domain", "clock_id", "observed_tick"],
            ),
            (
                session
                    .capture_randomness_draw(
                        &BoundaryContext::new("trace-1", "decision-1", "policy-1", "rng", 2),
                        "rng-seeded",
                        3,
                        "digest-sample",
                        None,
                    )
                    .expect("rng capture"),
                BoundaryClass::RandomnessDraw,
                ["draw_index", "generator_id", "sample_digest"],
            ),
            (
                session
                    .capture_filesystem_input(
                        &BoundaryContext::new("trace-2", "decision-2", "policy-2", "cache", 3),
                        "cache_read",
                        "digest-path",
                        "digest-content",
                        None,
                    )
                    .expect("filesystem capture"),
                BoundaryClass::FilesystemInput,
                ["content_digest", "operation", "path_digest"],
            ),
            (
                session
                    .capture_network_response(
                        &BoundaryContext::new("trace-3", "decision-3", "policy-3", "network", 4),
                        "digest-request",
                        "digest-response",
                        200,
                        None,
                    )
                    .expect("network capture"),
                BoundaryClass::NetworkResponse,
                ["request_digest", "response_digest", "status_code"],
            ),
            (
                session
                    .capture_module_resolution(
                        &BoundaryContext::new("trace-4", "decision-4", "policy-4", "module", 5),
                        "pkg:demo/widget",
                        "digest-referrer",
                        "digest-resolved",
                        None,
                    )
                    .expect("module capture"),
                BoundaryClass::ModuleResolution,
                ["referrer_digest", "resolved_path_digest", "specifier"],
            ),
            (
                session
                    .capture_scheduling_decision(
                        &BoundaryContext::new("trace-5", "decision-5", "policy-5", "scheduler", 6),
                        "ready",
                        "task-41",
                        "digest-ordering",
                        None,
                    )
                    .expect("scheduler capture"),
                BoundaryClass::SchedulingDecision,
                ["ordering_digest", "queue_id", "task_id"],
            ),
            (
                session
                    .capture_controller_override(
                        &BoundaryContext::new("trace-6", "decision-6", "policy-6", "controller", 7),
                        "router",
                        "force_safe_mode",
                        "digest-value",
                        None,
                    )
                    .expect("controller capture"),
                BoundaryClass::ControllerOverride,
                ["controller_id", "override_kind", "value_digest"],
            ),
            (
                session
                    .capture_external_policy_read(
                        &BoundaryContext::new("trace-7", "decision-7", "policy-7", "policy", 8),
                        "risk-router",
                        "digest-policy",
                        9,
                        None,
                    )
                    .expect("policy capture"),
                BoundaryClass::ExternalPolicyRead,
                ["policy_digest", "policy_epoch", "policy_name"],
            ),
            (
                session
                    .capture_hardware_surface_read(
                        &BoundaryContext::new("trace-8", "decision-8", "policy-8", "hardware", 9),
                        "tpm_quote",
                        "digest-measurement",
                        "digest-driver",
                        None,
                    )
                    .expect("hardware capture"),
                BoundaryClass::HardwareSurfaceRead,
                ["driver_fingerprint", "measurement_digest", "surface_kind"],
            ),
        ];

        for (record, expected_class, expected_fields) in captures {
            assert_eq!(record.boundary_class, expected_class);
            let actual_fields: Vec<_> = record.minimal_fields.keys().map(String::as_str).collect();
            assert_eq!(actual_fields, expected_fields);
        }
    }

    #[test]
    fn capture_rejects_unexpected_fields() {
        let mut session = BoundaryCaptureSession::default_v1();
        let context = BoundaryContext::new("trace-a", "decision-a", "policy-a", "fs", 10);
        let mut request = build_request(
            &context,
            BoundaryClass::FilesystemInput,
            None,
            [
                ("operation", "read".to_string()),
                ("path_digest", "path-digest".to_string()),
                ("content_digest", "content-digest".to_string()),
            ],
        );
        request
            .minimal_fields
            .insert("raw_path".to_string(), "/tmp/x".to_string());
        let error = session
            .capture_boundary(request)
            .expect_err("unexpected field");
        assert_eq!(
            error,
            BoundaryCaptureError::UnexpectedField {
                boundary_class: BoundaryClass::FilesystemInput,
                field: "raw_path".to_string(),
            }
        );
    }

    #[test]
    fn correlation_key_is_stable_for_same_identity_tuple() {
        let left = derive_correlation_key(
            BoundaryClass::ModuleResolution,
            2,
            "trace-a",
            "decision-a",
            "module-loader",
            42,
        );
        let right = derive_correlation_key(
            BoundaryClass::ModuleResolution,
            2,
            "trace-a",
            "decision-a",
            "module-loader",
            42,
        );
        assert_eq!(left, right);
    }

    #[test]
    fn escalation_reason_marks_record_for_follow_up() {
        let mut session = BoundaryCaptureSession::default_v1();
        let context = BoundaryContext::new("trace-b", "decision-b", "policy-b", "net", 77);
        let record = session
            .capture_network_response(
                &context,
                "request-digest",
                "response-digest",
                503,
                Some("network-rich-body-needed"),
            )
            .expect("capture succeeds");
        assert_eq!(record.sufficiency, ReplaySufficiency::NeedsEscalation);
        assert_eq!(
            record.escalation_reason.as_deref(),
            Some("network-rich-body-needed")
        );
    }

    #[test]
    fn capture_log_renders_jsonl() {
        let mut session = BoundaryCaptureSession::default_v1();
        let context = BoundaryContext::new("trace-c", "decision-c", "policy-c", "scheduler", 15);
        session
            .capture_scheduling_decision(&context, "ready", "task-1", "ordering-digest", None)
            .expect("capture succeeds");
        let rendered = session.log().render_jsonl().expect("jsonl renders");
        assert!(rendered.contains("\"boundary_class\":\"scheduling_decision\""));
        assert!(rendered.contains("\"correlation_key\":\"bcorr_"));
    }

    #[test]
    fn minimal_replay_plan_rejects_escalated_capture() {
        let mut session = BoundaryCaptureSession::default_v1();
        let context = BoundaryContext::new("trace-d", "decision-d", "policy-d", "controller", 22);
        session
            .capture_controller_override(
                &context,
                "router",
                "force_safe_mode",
                "digest-value",
                Some("interactive-controller-input"),
            )
            .expect("capture succeeds");

        let error = session
            .minimal_replay_plans()
            .expect_err("escalated capture must block minimal replay");
        assert_eq!(
            error,
            BoundaryCaptureError::ReplayNeedsEscalation {
                boundary_class: BoundaryClass::ControllerOverride,
                correlation_key: session.log().records()[0].correlation_key.clone(),
                reason: "interactive-controller-input".to_string(),
            }
        );
    }
}
