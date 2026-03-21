//! Declassification decision pipeline for cross-label information flows.
//!
//! Processes declassification requests through five stages:
//! 1. **Request** — runtime detects a flow requiring declassification.
//! 2. **Policy evaluation** — checks approved routes and conditions.
//! 3. **Loss assessment** — estimates potential harm from allowing.
//! 4. **Decision** — allow or deny based on policy and loss.
//! 5. **Signed receipt** — emits `DeclassificationReceipt` with replay linkage.
//!
//! Deterministic replay: given identical request, policy, and model state,
//! the pipeline produces an identical decision.
//!
//! Plan reference: Section 10.15 item 9I.7, bd-3hkk.
//! Dependencies: bd-1ovk (IFC artifact schemas), 10.5 (decision contracts).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ifc_artifacts::{
    DeclassificationDecision, DeclassificationReceipt, FlowPolicy, IfcSchemaVersion,
    IfcValidationError, Label,
};
use crate::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

// ---------------------------------------------------------------------------
// DeclassificationRequest — input to the pipeline
// ---------------------------------------------------------------------------

/// A request to declassify information flowing from a higher label to a
/// lower clearance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// Source sensitivity label.
    pub source_label: Label,
    /// Target sink clearance.
    pub sink_clearance: Label,
    /// Extension initiating the flow.
    pub extension_id: String,
    /// Code location (module::function or IR node).
    pub code_location: String,
    /// Trace ID for replay linkage.
    pub trace_id: String,
    /// Requested declassification route ID (from the flow policy).
    pub requested_route_id: String,
    /// Decision contract expected to authorize this declassification.
    pub decision_contract_id: String,
    /// Whether this is an emergency declassification.
    pub is_emergency: bool,
    /// Timestamp (unix ms).
    pub timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// PolicyEvaluation — result of checking the request against policy
// ---------------------------------------------------------------------------

/// Result of evaluating a declassification request against the flow policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEvalResult {
    /// Route found and conditions met.
    RouteApproved {
        route_id: String,
        conditions_met: Vec<String>,
    },
    /// Route found but conditions not met.
    ConditionsNotMet {
        route_id: String,
        failed_conditions: Vec<String>,
    },
    /// No matching route in the policy.
    NoMatchingRoute,
    /// Policy itself is unavailable or invalid.
    PolicyUnavailable { reason: String },
}

impl PolicyEvalResult {
    /// Whether the evaluation found an approved route.
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::RouteApproved { .. })
    }
}

// ---------------------------------------------------------------------------
// LossAssessment — estimated harm from allowing the flow
// ---------------------------------------------------------------------------

/// Loss assessment for a potential declassification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossAssessment {
    /// Expected loss in millionths (1_000_000 = 1.0).
    pub expected_loss_milli: u64,
    /// Data sensitivity score (0-10000 basis points).
    pub data_sensitivity_bps: u16,
    /// Sink exposure surface score (0-10000 basis points).
    pub sink_exposure_bps: u16,
    /// Whether historical abuse was detected for this flow pattern.
    pub historical_abuse_detected: bool,
    /// Summary of the assessment.
    pub summary: String,
}

impl LossAssessment {
    /// Default threshold below which declassification is allowed (millionths).
    pub const DEFAULT_THRESHOLD_MILLI: u64 = 100_000; // 0.1

    /// Whether loss is below the given threshold.
    pub fn below_threshold(&self, threshold_milli: u64) -> bool {
        self.expected_loss_milli < threshold_milli
    }
}

// ---------------------------------------------------------------------------
// PipelineEvent — structured event for audit
// ---------------------------------------------------------------------------

/// Structured event emitted at each pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineEvent {
    /// Request ID.
    pub request_id: String,
    /// Trace ID.
    pub trace_id: String,
    /// Pipeline stage.
    pub stage: String,
    /// Outcome of this stage.
    pub outcome: String,
    /// Component.
    pub component: String,
    /// Error code if any.
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// PipelineError — errors from the declassification pipeline
// ---------------------------------------------------------------------------

/// Errors that can occur during declassification pipeline processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineError {
    /// Flow does not require declassification (already lattice-legal).
    FlowAlreadyLegal { source: Label, sink: Label },
    /// Policy is unavailable.
    PolicyUnavailable { reason: String },
    /// No matching route in policy.
    NoMatchingRoute { source: Label, sink: Label },
    /// Loss exceeds threshold.
    LossExceedsThreshold {
        expected_loss_milli: u64,
        threshold_milli: u64,
    },
    /// Emergency declassification expired.
    EmergencyExpired { request_id: String, expiry_ms: u64 },
    /// Signing error.
    SigningError { detail: String },
    /// Validation error.
    ValidationError(IfcValidationError),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FlowAlreadyLegal { source, sink } => {
                write!(f, "flow from {source} to {sink} is already lattice-legal")
            }
            Self::PolicyUnavailable { reason } => {
                write!(f, "policy unavailable: {reason}")
            }
            Self::NoMatchingRoute { source, sink } => {
                write!(f, "no declassification route from {source} to {sink}")
            }
            Self::LossExceedsThreshold {
                expected_loss_milli,
                threshold_milli,
            } => {
                write!(
                    f,
                    "loss {expected_loss_milli} exceeds threshold {threshold_milli}"
                )
            }
            Self::EmergencyExpired {
                request_id,
                expiry_ms,
            } => {
                write!(
                    f,
                    "emergency declassification {request_id} expired at {expiry_ms}"
                )
            }
            Self::SigningError { detail } => {
                write!(f, "signing error: {detail}")
            }
            Self::ValidationError(e) => write!(f, "validation error: {e}"),
        }
    }
}

impl std::error::Error for PipelineError {}

// ---------------------------------------------------------------------------
// PipelineConfig — configurable pipeline parameters
// ---------------------------------------------------------------------------

/// Configuration for the declassification pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Loss threshold below which declassification is auto-allowed (millionths).
    pub loss_threshold_milli: u64,
    /// Maximum emergency declassification duration (ms).
    pub emergency_max_duration_ms: u64,
    /// Whether to emit events at each stage.
    pub emit_stage_events: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            loss_threshold_milli: LossAssessment::DEFAULT_THRESHOLD_MILLI,
            emergency_max_duration_ms: 300_000, // 5 minutes
            emit_stage_events: true,
        }
    }
}

// ---------------------------------------------------------------------------
// EmergencyGrant — time-bounded emergency declassification
// ---------------------------------------------------------------------------

/// A time-bounded emergency declassification grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyGrant {
    /// Grant identifier.
    pub grant_id: String,
    /// Request that triggered this grant.
    pub request_id: String,
    /// Extension the grant is scoped to.
    pub extension_id: String,
    /// Source label.
    pub source_label: Label,
    /// Sink clearance.
    pub sink_clearance: Label,
    /// Decision contract the grant is scoped to.
    pub decision_contract_id: String,
    /// Expiry timestamp (unix ms).
    pub expiry_ms: u64,
    /// Whether post-incident review has been completed.
    pub review_completed: bool,
}

impl EmergencyGrant {
    /// Check if this grant has expired at the given time.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expiry_ms
    }
}

// ---------------------------------------------------------------------------
// DeclassificationPipeline — main pipeline orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the declassification decision pipeline.
///
/// Given a request and policy, evaluates through all stages and produces
/// a signed `DeclassificationReceipt`.
#[derive(Debug, Clone)]
pub struct DeclassificationPipeline {
    /// Pipeline configuration.
    config: PipelineConfig,
    /// Accumulated pipeline events.
    events: Vec<PipelineEvent>,
    /// Emitted receipts.
    receipts: Vec<DeclassificationReceipt>,
    /// Active emergency grants.
    emergency_grants: BTreeMap<String, EmergencyGrant>,
    /// Decision count for statistics.
    decision_count: u64,
    /// Allow count.
    allow_count: u64,
    /// Deny count.
    deny_count: u64,
    /// Latest successfully receipted request timestamp, used as the
    /// deterministic reference time for default stats snapshots.
    latest_timestamp_ms: u64,
}

impl Default for DeclassificationPipeline {
    fn default() -> Self {
        Self::new(PipelineConfig::default())
    }
}

impl DeclassificationPipeline {
    /// Create a new pipeline with the given configuration.
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
            receipts: Vec::new(),
            emergency_grants: BTreeMap::new(),
            decision_count: 0,
            allow_count: 0,
            deny_count: 0,
            latest_timestamp_ms: 0,
        }
    }

    /// Process a declassification request through the full pipeline.
    ///
    /// Returns a signed `DeclassificationReceipt` on success.
    pub fn process(
        &mut self,
        request: &DeclassificationRequest,
        policy: &FlowPolicy,
        loss: &LossAssessment,
        signing_key: &SigningKey,
    ) -> Result<DeclassificationReceipt, PipelineError> {
        // Stage 1: Request validation
        self.emit_stage_event(request, "request_validation", "started", None);

        if request.source_label.can_flow_to(&request.sink_clearance) {
            self.emit_stage_event(request, "request_validation", "flow_already_legal", None);
            return Err(PipelineError::FlowAlreadyLegal {
                source: request.source_label.clone(),
                sink: request.sink_clearance.clone(),
            });
        }

        self.emit_stage_event(
            request,
            "request_validation",
            "requires_declassification",
            None,
        );

        // Stage 2: Policy evaluation
        self.emit_stage_event(request, "policy_evaluation", "started", None);

        let policy_result = self.evaluate_policy(request, policy);
        if !policy_result.is_approved() {
            let (outcome, error_code) = match &policy_result {
                PolicyEvalResult::NoMatchingRoute => ("no_route", Some("no_matching_route")),
                PolicyEvalResult::ConditionsNotMet { .. } => {
                    ("conditions_not_met", Some("conditions_not_met"))
                }
                PolicyEvalResult::PolicyUnavailable { .. } => {
                    ("policy_unavailable", Some("policy_unavailable"))
                }
                PolicyEvalResult::RouteApproved { .. } => unreachable!(),
            };
            self.emit_stage_event(request, "policy_evaluation", outcome, error_code);

            // Check emergency pathway
            if request.is_emergency {
                return self.process_emergency(request, loss, signing_key);
            }

            return Err(match policy_result {
                PolicyEvalResult::NoMatchingRoute => PipelineError::NoMatchingRoute {
                    source: request.source_label.clone(),
                    sink: request.sink_clearance.clone(),
                },
                PolicyEvalResult::PolicyUnavailable { reason } => {
                    PipelineError::PolicyUnavailable { reason }
                }
                _ => PipelineError::NoMatchingRoute {
                    source: request.source_label.clone(),
                    sink: request.sink_clearance.clone(),
                },
            });
        }

        let route_id = match &policy_result {
            PolicyEvalResult::RouteApproved { route_id, .. } => route_id.clone(),
            _ => unreachable!(),
        };

        self.emit_stage_event(request, "policy_evaluation", "route_approved", None);

        // Stage 3: Loss assessment
        self.emit_stage_event(request, "loss_assessment", "started", None);

        if !loss.below_threshold(self.config.loss_threshold_milli) {
            self.emit_stage_event(
                request,
                "loss_assessment",
                "exceeds_threshold",
                Some("loss_exceeds_threshold"),
            );
            self.emit_stage_event(request, "decision", "deny", Some("loss_exceeds_threshold"));

            // Deny — loss too high
            let receipt = self.build_signed_receipt(
                request,
                DeclassificationDecision::Deny,
                &route_id,
                loss,
                signing_key,
                "loss exceeds threshold",
            )?;
            self.decision_count += 1;
            self.deny_count += 1;
            self.record_signed_receipt(request, &receipt);
            return Ok(receipt);
        }

        self.emit_stage_event(request, "loss_assessment", "below_threshold", None);

        // Stage 4: Decision — allow
        self.emit_stage_event(request, "decision", "allow", None);

        // Stage 5: Signed receipt
        let receipt = self.build_signed_receipt(
            request,
            DeclassificationDecision::Allow,
            &route_id,
            loss,
            signing_key,
            "policy evaluation passed, loss below threshold",
        )?;
        self.decision_count += 1;
        self.allow_count += 1;
        self.record_signed_receipt(request, &receipt);
        Ok(receipt)
    }

    /// Check for an active emergency grant.
    pub fn check_emergency_grant(
        &self,
        extension_id: &str,
        source: &Label,
        sink: &Label,
        decision_contract_id: &str,
        now_ms: u64,
    ) -> Option<&EmergencyGrant> {
        self.emergency_grants.values().find(|g| {
            g.extension_id == extension_id
                && g.source_label == *source
                && g.sink_clearance == *sink
                && g.decision_contract_id == decision_contract_id
                && !g.review_completed
                && !g.is_expired(now_ms)
        })
    }

    /// Mark an emergency grant as reviewed.
    pub fn complete_emergency_review(&mut self, grant_id: &str) -> bool {
        if let Some(grant) = self.emergency_grants.get_mut(grant_id) {
            grant.review_completed = true;
            true
        } else {
            false
        }
    }

    /// View accumulated events.
    pub fn events(&self) -> &[PipelineEvent] {
        &self.events
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<PipelineEvent> {
        std::mem::take(&mut self.events)
    }

    /// View emitted receipts.
    pub fn receipts(&self) -> &[DeclassificationReceipt] {
        &self.receipts
    }

    /// Pipeline statistics.
    pub fn stats(&self) -> PipelineStats {
        self.stats_at(self.latest_timestamp_ms)
    }

    /// Pipeline statistics at an explicit reference timestamp.
    pub fn stats_at(&self, now_ms: u64) -> PipelineStats {
        PipelineStats {
            decision_count: self.decision_count,
            allow_count: self.allow_count,
            deny_count: self.deny_count,
            emergency_grants_active: self
                .emergency_grants
                .values()
                .filter(|g| !g.review_completed && !g.is_expired(now_ms))
                .count() as u64,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn evaluate_policy(
        &self,
        request: &DeclassificationRequest,
        policy: &FlowPolicy,
    ) -> PolicyEvalResult {
        if policy.extension_id != request.extension_id {
            return PolicyEvalResult::PolicyUnavailable {
                reason: format!(
                    "policy extension {} does not match request extension {}",
                    policy.extension_id, request.extension_id
                ),
            };
        }

        // Find matching route
        for route in &policy.declassification_routes {
            if route.route_id == request.requested_route_id
                && route.source_label == request.source_label
                && route.target_clearance == request.sink_clearance
            {
                // All conditions are treated as met (condition evaluation
                // is delegated to the decision-contract layer).
                return PolicyEvalResult::RouteApproved {
                    route_id: route.route_id.clone(),
                    conditions_met: route.conditions.clone(),
                };
            }
        }
        PolicyEvalResult::NoMatchingRoute
    }

    fn process_emergency(
        &mut self,
        request: &DeclassificationRequest,
        loss: &LossAssessment,
        signing_key: &SigningKey,
    ) -> Result<DeclassificationReceipt, PipelineError> {
        self.emit_stage_event(request, "emergency_pathway", "started", None);

        let expiry_ms = request
            .timestamp_ms
            .saturating_add(self.config.emergency_max_duration_ms);
        let grant_id = format!("emg-{}", request.request_id);

        let grant = EmergencyGrant {
            grant_id: grant_id.clone(),
            request_id: request.request_id.clone(),
            extension_id: request.extension_id.clone(),
            source_label: request.source_label.clone(),
            sink_clearance: request.sink_clearance.clone(),
            decision_contract_id: request.decision_contract_id.clone(),
            expiry_ms,
            review_completed: false,
        };
        let receipt = self.build_signed_receipt(
            request,
            DeclassificationDecision::Allow,
            "emergency",
            loss,
            signing_key,
            "emergency declassification granted; post-incident review required",
        )?;

        self.emergency_grants.insert(grant_id, grant);
        self.emit_stage_event(request, "emergency_pathway", "grant_issued", None);
        self.decision_count += 1;
        self.allow_count += 1;
        self.record_signed_receipt(request, &receipt);
        Ok(receipt)
    }

    fn build_signed_receipt(
        &self,
        request: &DeclassificationRequest,
        decision: DeclassificationDecision,
        route_ref: &str,
        loss: &LossAssessment,
        signing_key: &SigningKey,
        summary: &str,
    ) -> Result<DeclassificationReceipt, PipelineError> {
        let vk = signing_key.verification_key();
        let mut receipt = DeclassificationReceipt {
            receipt_id: format!("rcpt-{}", request.request_id),
            source_label: request.source_label.clone(),
            sink_clearance: request.sink_clearance.clone(),
            declassification_route_ref: route_ref.to_string(),
            decision_contract_id: request.decision_contract_id.clone(),
            policy_evaluation_summary: summary.to_string(),
            loss_assessment_milli: loss.expected_loss_milli,
            decision,
            authorized_by: vk,
            replay_linkage: request.trace_id.clone(),
            timestamp_ms: request.timestamp_ms,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        receipt
            .sign(signing_key)
            .map_err(|e| PipelineError::SigningError {
                detail: e.to_string(),
            })?;

        Ok(receipt)
    }

    fn record_signed_receipt(
        &mut self,
        request: &DeclassificationRequest,
        receipt: &DeclassificationReceipt,
    ) {
        self.latest_timestamp_ms = self.latest_timestamp_ms.max(request.timestamp_ms);
        self.emit_stage_event(request, "signed_receipt", "emitted", None);
        self.receipts.push(receipt.clone());
    }

    fn emit_stage_event(
        &mut self,
        request: &DeclassificationRequest,
        stage: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        if self.config.emit_stage_events {
            self.events.push(PipelineEvent {
                request_id: request.request_id.clone(),
                trace_id: request.trace_id.clone(),
                stage: stage.to_string(),
                outcome: outcome.to_string(),
                component: "declassification_pipeline".to_string(),
                error_code: error_code.map(|s| s.to_string()),
            });
        }
    }
}

/// Pipeline statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStats {
    pub decision_count: u64,
    pub allow_count: u64,
    pub deny_count: u64,
    pub emergency_grants_active: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ifc_artifacts::DeclassificationRoute;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes([42u8; 32])
    }

    fn make_policy() -> FlowPolicy {
        FlowPolicy {
            policy_id: "pol-test".to_string(),
            extension_id: "ext-test".to_string(),
            label_classes: [
                Label::Public,
                Label::Internal,
                Label::Confidential,
                Label::Secret,
            ]
            .into_iter()
            .collect(),
            clearance_classes: [
                Label::Public,
                Label::Internal,
                Label::Confidential,
                Label::Secret,
            ]
            .into_iter()
            .collect(),
            allowed_flows: vec![],
            prohibited_flows: vec![],
            declassification_routes: vec![
                DeclassificationRoute {
                    route_id: "declass-secret-internal".to_string(),
                    source_label: Label::Secret,
                    target_clearance: Label::Internal,
                    conditions: vec!["audit_approval".to_string()],
                },
                DeclassificationRoute {
                    route_id: "declass-conf-public".to_string(),
                    source_label: Label::Confidential,
                    target_clearance: Label::Public,
                    conditions: vec!["redaction_applied".to_string()],
                },
            ],
            epoch_id: 1,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        }
    }

    fn make_request(route_id: &str, source: Label, sink: Label) -> DeclassificationRequest {
        DeclassificationRequest {
            request_id: format!("req-{route_id}"),
            source_label: source,
            sink_clearance: sink,
            extension_id: "ext-test".to_string(),
            code_location: "module::func".to_string(),
            trace_id: "trace-001".to_string(),
            requested_route_id: route_id.to_string(),
            decision_contract_id: "decision-contract-test".to_string(),
            is_emergency: false,
            timestamp_ms: 1_700_000_000_000,
        }
    }

    fn low_loss() -> LossAssessment {
        LossAssessment {
            expected_loss_milli: 10_000, // 0.01
            data_sensitivity_bps: 2000,
            sink_exposure_bps: 1000,
            historical_abuse_detected: false,
            summary: "low risk".to_string(),
        }
    }

    fn high_loss() -> LossAssessment {
        LossAssessment {
            expected_loss_milli: 500_000, // 0.5
            data_sensitivity_bps: 9000,
            sink_exposure_bps: 8000,
            historical_abuse_detected: true,
            summary: "high risk".to_string(),
        }
    }

    // -- Pipeline: successful declassification --

    #[test]
    fn successful_declassification_produces_receipt() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let key = test_key();

        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &key)
            .unwrap();
        assert_eq!(receipt.decision, DeclassificationDecision::Allow);
        assert_eq!(receipt.source_label, Label::Secret);
        assert_eq!(receipt.sink_clearance, Label::Internal);
        assert_eq!(receipt.decision_contract_id, request.decision_contract_id);
        assert!(!receipt.signature.is_sentinel());
        receipt.verify(&key.verification_key()).unwrap();
    }

    #[test]
    fn successful_declassification_emits_events() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        let events = pipeline.events();
        assert!(events.len() >= 5);

        // Check stage progression
        let stages: Vec<&str> = events.iter().map(|e| e.stage.as_str()).collect();
        assert!(stages.contains(&"request_validation"));
        assert!(stages.contains(&"policy_evaluation"));
        assert!(stages.contains(&"loss_assessment"));
        assert!(stages.contains(&"decision"));
        assert!(stages.contains(&"signed_receipt"));
    }

    #[test]
    fn receipt_stored_in_pipeline() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert_eq!(pipeline.receipts().len(), 1);
    }

    // -- Pipeline: denial cases --

    #[test]
    fn flow_already_legal_rejected() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        // Public -> Internal is lattice-legal
        let request = make_request("declass-any", Label::Public, Label::Internal);

        let err = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap_err();
        assert!(matches!(err, PipelineError::FlowAlreadyLegal { .. }));
    }

    #[test]
    fn no_matching_route_denied() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        // Secret -> Public has no route
        let request = make_request("nonexistent-route", Label::Secret, Label::Public);

        let err = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap_err();
        assert!(matches!(err, PipelineError::NoMatchingRoute { .. }));
    }

    #[test]
    fn high_loss_denied_with_receipt() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

        let result = pipeline.process(&request, &policy, &high_loss(), &test_key());
        // High loss should produce a deny receipt (not an error)
        let receipt = result.unwrap();
        assert_eq!(receipt.decision, DeclassificationDecision::Deny);
    }

    // -- Pipeline: emergency pathway --

    #[test]
    fn emergency_declassification_bypasses_route_check() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("nonexistent-route", Label::Secret, Label::Public);
        request.is_emergency = true;

        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert_eq!(receipt.decision, DeclassificationDecision::Allow);
        assert_eq!(receipt.declassification_route_ref, "emergency");
        assert_eq!(receipt.decision_contract_id, request.decision_contract_id);
        assert_eq!(
            receipt.replay_command(),
            "frankenctl replay run --trace <trace.json> --mode strict"
        );
    }

    #[test]
    fn emergency_creates_grant() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("bad-route", Label::Secret, Label::Public);
        request.is_emergency = true;

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        let grant = pipeline
            .check_emergency_grant(
                &request.extension_id,
                &Label::Secret,
                &Label::Public,
                &request.decision_contract_id,
                request.timestamp_ms,
            )
            .unwrap();
        assert!(!grant.review_completed);
        assert!(!grant.is_expired(request.timestamp_ms));
        assert_eq!(grant.extension_id, request.extension_id);
        assert_eq!(grant.decision_contract_id, request.decision_contract_id);
    }

    #[test]
    fn emergency_grant_expires() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("bad-route", Label::Secret, Label::Public);
        request.is_emergency = true;

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        // Check after expiry
        let far_future = request.timestamp_ms + 1_000_000;
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Public,
                    &request.decision_contract_id,
                    far_future,
                )
                .is_none()
        );
    }

    #[test]
    fn emergency_review_completion() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("bad-route", Label::Secret, Label::Public);
        request.is_emergency = true;

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        let grant_id = format!("emg-{}", request.request_id);
        assert!(pipeline.complete_emergency_review(&grant_id));
        assert!(!pipeline.complete_emergency_review("nonexistent"));
    }

    // -- Pipeline: statistics --

    #[test]
    fn stats_track_decisions() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let key = test_key();

        // Allow
        let req1 = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        pipeline.process(&req1, &policy, &low_loss(), &key).unwrap();

        // Deny (high loss)
        let mut req2 = make_request("declass-conf-public", Label::Confidential, Label::Public);
        req2.request_id = "req-2".to_string();
        pipeline
            .process(&req2, &policy, &high_loss(), &key)
            .unwrap();

        let stats = pipeline.stats();
        assert_eq!(stats.decision_count, 2);
        assert_eq!(stats.allow_count, 1);
        assert_eq!(stats.deny_count, 1);
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_replay_100_times() {
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let key = test_key();
        let loss = low_loss();

        let mut receipts = Vec::new();
        for _ in 0..100 {
            let mut pipeline = DeclassificationPipeline::default();
            let receipt = pipeline.process(&request, &policy, &loss, &key).unwrap();
            receipts.push(receipt);
        }

        // All receipts should be identical
        let first = &receipts[0];
        for r in &receipts[1..] {
            assert_eq!(r.decision, first.decision);
            assert_eq!(r.source_label, first.source_label);
            assert_eq!(r.sink_clearance, first.sink_clearance);
            assert_eq!(r.loss_assessment_milli, first.loss_assessment_milli);
            assert_eq!(r.replay_linkage, first.replay_linkage);
            // Signatures should also be identical (same key, same preimage)
            assert_eq!(r.signature, first.signature);
        }
    }

    // -- Serde round-trips --

    #[test]
    fn request_serde_roundtrip() {
        let req = make_request("route-1", Label::Secret, Label::Internal);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DeclassificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn policy_eval_result_serde_roundtrip() {
        let results = [
            PolicyEvalResult::RouteApproved {
                route_id: "r1".to_string(),
                conditions_met: vec!["c1".to_string()],
            },
            PolicyEvalResult::ConditionsNotMet {
                route_id: "r1".to_string(),
                failed_conditions: vec!["c2".to_string()],
            },
            PolicyEvalResult::NoMatchingRoute,
            PolicyEvalResult::PolicyUnavailable {
                reason: "gone".to_string(),
            },
        ];
        for r in results {
            let json = serde_json::to_string(&r).unwrap();
            let parsed: PolicyEvalResult = serde_json::from_str(&json).unwrap();
            assert_eq!(r, parsed);
        }
    }

    #[test]
    fn loss_assessment_serde_roundtrip() {
        let loss = low_loss();
        let json = serde_json::to_string(&loss).unwrap();
        let parsed: LossAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(loss, parsed);
    }

    #[test]
    fn pipeline_event_serde_roundtrip() {
        let event = PipelineEvent {
            request_id: "req-1".to_string(),
            trace_id: "trace-1".to_string(),
            stage: "policy_evaluation".to_string(),
            outcome: "route_approved".to_string(),
            component: "declassification_pipeline".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: PipelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn pipeline_error_display() {
        let err = PipelineError::FlowAlreadyLegal {
            source: Label::Public,
            sink: Label::Internal,
        };
        assert!(err.to_string().contains("already lattice-legal"));

        let err = PipelineError::LossExceedsThreshold {
            expected_loss_milli: 500_000,
            threshold_milli: 100_000,
        };
        assert!(err.to_string().contains("500000"));
    }

    #[test]
    fn pipeline_error_serde_roundtrip() {
        let errors = [
            PipelineError::FlowAlreadyLegal {
                source: Label::Public,
                sink: Label::Internal,
            },
            PipelineError::NoMatchingRoute {
                source: Label::Secret,
                sink: Label::Public,
            },
            PipelineError::PolicyUnavailable {
                reason: "gone".to_string(),
            },
            PipelineError::LossExceedsThreshold {
                expected_loss_milli: 500_000,
                threshold_milli: 100_000,
            },
            PipelineError::SigningError {
                detail: "bad key".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let parsed: PipelineError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, parsed);
        }
    }

    #[test]
    fn pipeline_config_serde_roundtrip() {
        let config = PipelineConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PipelineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn emergency_grant_serde_roundtrip() {
        let grant = EmergencyGrant {
            grant_id: "emg-1".to_string(),
            request_id: "req-1".to_string(),
            extension_id: "ext-test".to_string(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            decision_contract_id: "decision-contract-test".to_string(),
            expiry_ms: 1_700_000_300_000,
            review_completed: false,
        };
        let json = serde_json::to_string(&grant).unwrap();
        let parsed: EmergencyGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, parsed);
    }

    #[test]
    fn pipeline_stats_serde_roundtrip() {
        let stats = PipelineStats {
            decision_count: 10,
            allow_count: 7,
            deny_count: 3,
            emergency_grants_active: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: PipelineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, parsed);
    }

    // -- Loss assessment --

    #[test]
    fn loss_below_threshold() {
        let loss = low_loss();
        assert!(loss.below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
    }

    #[test]
    fn loss_above_threshold() {
        let loss = high_loss();
        assert!(!loss.below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
    }

    // -- Event component field stable --

    #[test]
    fn event_component_field_stable() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        for event in pipeline.events() {
            assert_eq!(event.component, "declassification_pipeline");
        }
    }

    // -- Drain events --

    #[test]
    fn drain_events_clears() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert!(!pipeline.events().is_empty());

        let drained = pipeline.drain_events();
        assert!(!drained.is_empty());
        assert!(pipeline.events().is_empty());
    }

    // -- Multiple declassifications --

    #[test]
    fn multiple_routes_independently_evaluated() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let key = test_key();

        let r1 = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let r2 = make_request("declass-conf-public", Label::Confidential, Label::Public);

        let receipt1 = pipeline.process(&r1, &policy, &low_loss(), &key).unwrap();
        let receipt2 = pipeline.process(&r2, &policy, &low_loss(), &key).unwrap();

        assert_eq!(
            receipt1.declassification_route_ref,
            "declass-secret-internal"
        );
        assert_eq!(receipt2.declassification_route_ref, "declass-conf-public");
        assert_eq!(pipeline.receipts().len(), 2);
    }

    // -- Events disabled --

    #[test]
    fn events_disabled_when_configured() {
        let config = PipelineConfig {
            emit_stage_events: false,
            ..PipelineConfig::default()
        };
        let mut pipeline = DeclassificationPipeline::new(config);
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert!(pipeline.events().is_empty());
    }

    // -- Enrichment: PipelineConfig defaults --

    #[test]
    fn pipeline_config_default_values() {
        let cfg = PipelineConfig::default();
        assert_eq!(
            cfg.loss_threshold_milli,
            LossAssessment::DEFAULT_THRESHOLD_MILLI
        );
        assert_eq!(cfg.emergency_max_duration_ms, 300_000);
        assert!(cfg.emit_stage_events);
    }

    // -- Enrichment: LossAssessment threshold constant --

    #[test]
    fn loss_assessment_default_threshold_value() {
        assert_eq!(LossAssessment::DEFAULT_THRESHOLD_MILLI, 100_000);
    }

    #[test]
    fn loss_at_exact_threshold_not_below() {
        let loss = LossAssessment {
            expected_loss_milli: 100_000,
            data_sensitivity_bps: 5000,
            sink_exposure_bps: 5000,
            historical_abuse_detected: false,
            summary: "at threshold".to_string(),
        };
        // below_threshold uses strict <, so exact threshold is NOT below
        assert!(!loss.below_threshold(100_000));
    }

    // -- Enrichment: PolicyEvalResult is_approved --

    #[test]
    fn policy_eval_result_is_approved_all_variants() {
        assert!(
            PolicyEvalResult::RouteApproved {
                route_id: "r".to_string(),
                conditions_met: vec![],
            }
            .is_approved()
        );

        assert!(
            !PolicyEvalResult::ConditionsNotMet {
                route_id: "r".to_string(),
                failed_conditions: vec!["c".to_string()],
            }
            .is_approved()
        );

        assert!(!PolicyEvalResult::NoMatchingRoute.is_approved());

        assert!(
            !PolicyEvalResult::PolicyUnavailable {
                reason: "gone".to_string(),
            }
            .is_approved()
        );
    }

    // -- Enrichment: EmergencyGrant expiry boundary --

    #[test]
    fn emergency_grant_expired_at_exact_expiry() {
        let grant = EmergencyGrant {
            grant_id: "g".to_string(),
            request_id: "r".to_string(),
            extension_id: "ext-test".to_string(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            decision_contract_id: "decision-contract-test".to_string(),
            expiry_ms: 1000,
            review_completed: false,
        };
        assert!(!grant.is_expired(999));
        assert!(grant.is_expired(1000)); // >= means expired
        assert!(grant.is_expired(1001));
    }

    // -- Enrichment: Pipeline starts empty --

    #[test]
    fn pipeline_starts_empty() {
        let pipeline = DeclassificationPipeline::default();
        assert!(pipeline.events().is_empty());
        assert!(pipeline.receipts().is_empty());
        let stats = pipeline.stats();
        assert_eq!(stats.decision_count, 0);
        assert_eq!(stats.allow_count, 0);
        assert_eq!(stats.deny_count, 0);
        assert_eq!(stats.emergency_grants_active, 0);
    }

    // -- Enrichment: PipelineError is std::error::Error --

    #[test]
    fn pipeline_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(PipelineError::PolicyUnavailable {
            reason: "test".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment: PipelineError Display all variants --

    #[test]
    fn pipeline_error_display_all_variants() {
        let variants: [PipelineError; 7] = [
            PipelineError::FlowAlreadyLegal {
                source: Label::Public,
                sink: Label::Internal,
            },
            PipelineError::PolicyUnavailable {
                reason: "unavail".to_string(),
            },
            PipelineError::NoMatchingRoute {
                source: Label::Secret,
                sink: Label::Public,
            },
            PipelineError::LossExceedsThreshold {
                expected_loss_milli: 500,
                threshold_milli: 100,
            },
            PipelineError::EmergencyExpired {
                request_id: "req-1".to_string(),
                expiry_ms: 999,
            },
            PipelineError::SigningError {
                detail: "bad key".to_string(),
            },
            PipelineError::ValidationError(IfcValidationError::EmptyClaim {
                claim_id: "c-1".to_string(),
            }),
        ];
        assert_eq!(variants.len(), 7, "must cover all PipelineError variants");
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // -- Enrichment: policy extension mismatch --

    #[test]
    fn policy_extension_mismatch_returns_error() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        request.extension_id = "wrong-extension".to_string();

        let err = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap_err();
        assert!(matches!(err, PipelineError::PolicyUnavailable { .. }));
    }

    // -- Enrichment: emergency grant not visible after review --

    #[test]
    fn emergency_grant_not_visible_after_review_completion() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("bad-route", Label::Secret, Label::Public);
        request.is_emergency = true;

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        let grant_id = format!("emg-{}", request.request_id);
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Public,
                    &request.decision_contract_id,
                    request.timestamp_ms,
                )
                .is_some()
        );

        pipeline.complete_emergency_review(&grant_id);
        // After review, grant should no longer be found
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Public,
                    &request.decision_contract_id,
                    request.timestamp_ms,
                )
                .is_none()
        );
    }

    // -- Enrichment batch 2: Display uniqueness, determinism, boundary --

    #[test]
    fn pipeline_error_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let variants: [PipelineError; 7] = [
            PipelineError::FlowAlreadyLegal {
                source: Label::Public,
                sink: Label::Internal,
            },
            PipelineError::PolicyUnavailable {
                reason: "gone".to_string(),
            },
            PipelineError::NoMatchingRoute {
                source: Label::Secret,
                sink: Label::Public,
            },
            PipelineError::LossExceedsThreshold {
                expected_loss_milli: 500,
                threshold_milli: 100,
            },
            PipelineError::EmergencyExpired {
                request_id: "req-1".to_string(),
                expiry_ms: 999,
            },
            PipelineError::SigningError {
                detail: "bad key".to_string(),
            },
            PipelineError::ValidationError(IfcValidationError::EmptyClaim {
                claim_id: "c-1".to_string(),
            }),
        ];
        let set: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            set.len(),
            variants.len(),
            "all PipelineError Display strings must be unique"
        );
    }

    #[test]
    fn policy_eval_result_serde_all_variants_unique_display() {
        use std::collections::BTreeSet;
        let variants = [
            PolicyEvalResult::RouteApproved {
                route_id: "r1".to_string(),
                conditions_met: vec!["c1".to_string()],
            },
            PolicyEvalResult::ConditionsNotMet {
                route_id: "r1".to_string(),
                failed_conditions: vec!["c2".to_string()],
            },
            PolicyEvalResult::NoMatchingRoute,
            PolicyEvalResult::PolicyUnavailable {
                reason: "gone".to_string(),
            },
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(
            set.len(),
            variants.len(),
            "all PolicyEvalResult serde forms must be unique"
        );
    }

    #[test]
    fn receipt_signature_is_not_sentinel() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        let sentinel = Signature::from_bytes(SIGNATURE_SENTINEL);
        assert_ne!(receipt.signature, sentinel, "receipt must be signed");
    }

    #[test]
    fn receipt_replay_linkage_not_empty() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert!(!receipt.replay_linkage.is_empty());
    }

    #[test]
    fn request_serde_preserves_emergency_flag() {
        let mut req = make_request("route-1", Label::Secret, Label::Internal);
        req.is_emergency = true;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DeclassificationRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_emergency);
    }

    #[test]
    fn stats_emergency_grants_tracked() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("bad-route", Label::Secret, Label::Public);
        request.is_emergency = true;

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        let stats = pipeline.stats();
        assert_eq!(stats.emergency_grants_active, 1);
    }

    #[test]
    fn flow_already_legal_public_to_public() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-public-public", Label::Public, Label::Public);
        let err = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap_err();
        assert!(matches!(err, PipelineError::FlowAlreadyLegal { .. }));
    }

    #[test]
    fn receipts_accumulate_across_calls() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let key = test_key();

        for i in 0..5 {
            let mut req = make_request("declass-secret-internal", Label::Secret, Label::Internal);
            req.request_id = format!("req-{i}");
            pipeline.process(&req, &policy, &low_loss(), &key).unwrap();
        }
        assert_eq!(pipeline.receipts().len(), 5);
    }

    // -- Enrichment batch 3: clone, serde, determinism, stats, error paths --

    #[test]
    fn receipt_clone_equality() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        let cloned = receipt.clone();
        assert_eq!(receipt, cloned);
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DeclassificationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn request_serde_roundtrip_enrichment() {
        let request = make_request("route-1", Label::Secret, Label::Internal);
        let json = serde_json::to_string(&request).unwrap();
        let back: DeclassificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request, back);
    }

    #[test]
    fn pipeline_default_stats_are_zero() {
        let pipeline = DeclassificationPipeline::default();
        let stats = pipeline.stats();
        assert_eq!(stats.decision_count, 0);
        assert_eq!(stats.allow_count, 0);
        assert_eq!(stats.deny_count, 0);
        assert_eq!(stats.emergency_grants_active, 0);
    }

    #[test]
    fn pipeline_default_receipts_empty() {
        let pipeline = DeclassificationPipeline::default();
        assert!(pipeline.receipts().is_empty());
    }

    #[test]
    fn stats_increments_on_successful_process() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let key = test_key();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        pipeline
            .process(&request, &policy, &low_loss(), &key)
            .unwrap();
        let stats = pipeline.stats();
        assert_eq!(stats.decision_count, 1);
        assert_eq!(stats.allow_count, 1);
    }

    #[test]
    fn pipeline_error_serde_all_variants() {
        let variants: [PipelineError; 6] = [
            PipelineError::FlowAlreadyLegal {
                source: Label::Public,
                sink: Label::Internal,
            },
            PipelineError::PolicyUnavailable {
                reason: "offline".to_string(),
            },
            PipelineError::NoMatchingRoute {
                source: Label::Secret,
                sink: Label::Public,
            },
            PipelineError::LossExceedsThreshold {
                expected_loss_milli: 999,
                threshold_milli: 100,
            },
            PipelineError::EmergencyExpired {
                request_id: "r1".to_string(),
                expiry_ms: 500,
            },
            PipelineError::SigningError {
                detail: "fail".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: PipelineError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn label_serde_all_variants() {
        let labels = [
            Label::Public,
            Label::Internal,
            Label::Secret,
            Label::TopSecret,
        ];
        for l in &labels {
            let json = serde_json::to_string(l).unwrap();
            let back: Label = serde_json::from_str(&json).unwrap();
            assert_eq!(*l, back);
        }
    }

    #[test]
    fn deterministic_receipts_across_runs() {
        let run = || {
            let mut pipeline = DeclassificationPipeline::default();
            let policy = make_policy();
            let key = test_key();
            let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
            pipeline
                .process(&request, &policy, &low_loss(), &key)
                .unwrap()
        };
        let r1 = run();
        let r2 = run();
        assert_eq!(r1.receipt_id, r2.receipt_id);
        assert_eq!(r1.source_label, r2.source_label);
        assert_eq!(r1.sink_clearance, r2.sink_clearance);
    }

    #[test]
    fn receipt_json_field_presence() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"receipt_id\""));
        assert!(json.contains("\"source_label\""));
        assert!(json.contains("\"sink_clearance\""));
        assert!(json.contains("\"decision\""));
    }

    #[test]
    fn stats_serde_roundtrip() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let key = test_key();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        pipeline
            .process(&request, &policy, &low_loss(), &key)
            .unwrap();
        let stats = pipeline.stats();
        let json = serde_json::to_string(&stats).unwrap();
        let back: PipelineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    // ===================================================================
    // Enrichment batch 4: ~55 new tests across all 10 categories
    // ===================================================================

    // -- Category 1: Copy semantics --

    #[test]
    fn declass_decision_copy_semantics() {
        let a = DeclassificationDecision::Allow;
        let b = a; // copy
        assert_eq!(a, b);
        let c = DeclassificationDecision::Deny;
        let d = c;
        assert_eq!(c, d);
    }

    #[test]
    fn ifc_schema_version_copy_semantics() {
        let v = IfcSchemaVersion::CURRENT;
        let w = v; // copy
        assert_eq!(v, w);
    }

    // -- Category 2: Debug distinctness --

    #[test]
    fn policy_eval_result_debug_distinctness() {
        use std::collections::BTreeSet;
        let variants = [
            PolicyEvalResult::RouteApproved {
                route_id: "r1".into(),
                conditions_met: vec!["c".into()],
            },
            PolicyEvalResult::ConditionsNotMet {
                route_id: "r1".into(),
                failed_conditions: vec!["f".into()],
            },
            PolicyEvalResult::NoMatchingRoute,
            PolicyEvalResult::PolicyUnavailable {
                reason: "gone".into(),
            },
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn pipeline_error_debug_distinctness() {
        use std::collections::BTreeSet;
        let variants: [PipelineError; 7] = [
            PipelineError::FlowAlreadyLegal {
                source: Label::Public,
                sink: Label::Internal,
            },
            PipelineError::PolicyUnavailable { reason: "x".into() },
            PipelineError::NoMatchingRoute {
                source: Label::Secret,
                sink: Label::Public,
            },
            PipelineError::LossExceedsThreshold {
                expected_loss_milli: 500,
                threshold_milli: 100,
            },
            PipelineError::EmergencyExpired {
                request_id: "r".into(),
                expiry_ms: 1,
            },
            PipelineError::SigningError { detail: "d".into() },
            PipelineError::ValidationError(IfcValidationError::EmptyClaim {
                claim_id: "c".into(),
            }),
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn declass_decision_debug_distinctness() {
        use std::collections::BTreeSet;
        let set: BTreeSet<String> = [
            DeclassificationDecision::Allow,
            DeclassificationDecision::Deny,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(set.len(), 2);
    }

    // -- Category 3: Serde variant distinctness --

    #[test]
    fn pipeline_error_serde_variant_distinctness() {
        use std::collections::BTreeSet;
        let variants: [PipelineError; 7] = [
            PipelineError::FlowAlreadyLegal {
                source: Label::Public,
                sink: Label::Internal,
            },
            PipelineError::PolicyUnavailable { reason: "x".into() },
            PipelineError::NoMatchingRoute {
                source: Label::Secret,
                sink: Label::Public,
            },
            PipelineError::LossExceedsThreshold {
                expected_loss_milli: 500,
                threshold_milli: 100,
            },
            PipelineError::EmergencyExpired {
                request_id: "r".into(),
                expiry_ms: 1,
            },
            PipelineError::SigningError { detail: "d".into() },
            PipelineError::ValidationError(IfcValidationError::EmptyClaim {
                claim_id: "c".into(),
            }),
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn declass_decision_serde_variant_distinctness() {
        use std::collections::BTreeSet;
        let set: BTreeSet<String> = [
            DeclassificationDecision::Allow,
            DeclassificationDecision::Deny,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
        assert_eq!(set.len(), 2);
    }

    // -- Category 4: Clone independence --

    #[test]
    fn request_clone_independence() {
        let original = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let mut cloned = original.clone();
        cloned.request_id = "mutated".to_string();
        cloned.is_emergency = true;
        assert_ne!(original.request_id, cloned.request_id);
        assert!(!original.is_emergency);
    }

    #[test]
    fn loss_assessment_clone_independence() {
        let original = low_loss();
        let mut cloned = original.clone();
        cloned.expected_loss_milli = 999_999;
        cloned.historical_abuse_detected = true;
        assert_eq!(original.expected_loss_milli, 10_000);
        assert!(!original.historical_abuse_detected);
    }

    #[test]
    fn pipeline_config_clone_independence() {
        let original = PipelineConfig::default();
        let mut cloned = original.clone();
        cloned.loss_threshold_milli = 0;
        cloned.emit_stage_events = false;
        assert_eq!(
            original.loss_threshold_milli,
            LossAssessment::DEFAULT_THRESHOLD_MILLI
        );
        assert!(original.emit_stage_events);
        // Use cloned to silence warning
        assert_eq!(cloned.loss_threshold_milli, 0);
        assert!(!cloned.emit_stage_events);
    }

    #[test]
    fn emergency_grant_clone_independence() {
        let original = EmergencyGrant {
            grant_id: "g-1".to_string(),
            request_id: "r-1".to_string(),
            extension_id: "ext-test".to_string(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            decision_contract_id: "decision-contract-test".to_string(),
            expiry_ms: 5000,
            review_completed: false,
        };
        let mut cloned = original.clone();
        cloned.review_completed = true;
        cloned.expiry_ms = 0;
        assert!(!original.review_completed);
        assert_eq!(original.expiry_ms, 5000);
    }

    #[test]
    fn pipeline_event_clone_independence() {
        let original = PipelineEvent {
            request_id: "r1".to_string(),
            trace_id: "t1".to_string(),
            stage: "loss_assessment".to_string(),
            outcome: "below_threshold".to_string(),
            component: "declassification_pipeline".to_string(),
            error_code: None,
        };
        let mut cloned = original.clone();
        cloned.outcome = "exceeded".to_string();
        cloned.error_code = Some("ERR".to_string());
        assert_eq!(original.outcome, "below_threshold");
        assert!(original.error_code.is_none());
    }

    #[test]
    fn pipeline_stats_clone_independence() {
        let original = PipelineStats {
            decision_count: 10,
            allow_count: 7,
            deny_count: 3,
            emergency_grants_active: 1,
        };
        let mut cloned = original.clone();
        cloned.decision_count = 0;
        assert_eq!(original.decision_count, 10);
        assert_eq!(cloned.decision_count, 0);
    }

    #[test]
    fn policy_eval_result_clone_independence() {
        let original = PolicyEvalResult::RouteApproved {
            route_id: "r1".to_string(),
            conditions_met: vec!["c1".to_string()],
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
        // The Clone should produce an equal but independent value
        let json_orig = serde_json::to_string(&original).unwrap();
        let json_clone = serde_json::to_string(&cloned).unwrap();
        assert_eq!(json_orig, json_clone);
    }

    // -- Category 5: JSON field-name stability --

    #[test]
    fn request_json_field_names_stable() {
        let req = make_request("r1", Label::Secret, Label::Internal);
        let json = serde_json::to_string(&req).unwrap();
        for field in &[
            "request_id",
            "source_label",
            "sink_clearance",
            "extension_id",
            "code_location",
            "trace_id",
            "requested_route_id",
            "decision_contract_id",
            "is_emergency",
            "timestamp_ms",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn loss_assessment_json_field_names_stable() {
        let loss = low_loss();
        let json = serde_json::to_string(&loss).unwrap();
        for field in &[
            "expected_loss_milli",
            "data_sensitivity_bps",
            "sink_exposure_bps",
            "historical_abuse_detected",
            "summary",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn pipeline_event_json_field_names_stable() {
        let event = PipelineEvent {
            request_id: "r".into(),
            trace_id: "t".into(),
            stage: "s".into(),
            outcome: "o".into(),
            component: "c".into(),
            error_code: Some("e".into()),
        };
        let json = serde_json::to_string(&event).unwrap();
        for field in &[
            "request_id",
            "trace_id",
            "stage",
            "outcome",
            "component",
            "error_code",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn pipeline_config_json_field_names_stable() {
        let cfg = PipelineConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        for field in &[
            "loss_threshold_milli",
            "emergency_max_duration_ms",
            "emit_stage_events",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn emergency_grant_json_field_names_stable() {
        let grant = EmergencyGrant {
            grant_id: "g".into(),
            request_id: "r".into(),
            extension_id: "ext-test".into(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            decision_contract_id: "decision-contract-test".into(),
            expiry_ms: 100,
            review_completed: false,
        };
        let json = serde_json::to_string(&grant).unwrap();
        for field in &[
            "grant_id",
            "request_id",
            "extension_id",
            "source_label",
            "sink_clearance",
            "decision_contract_id",
            "expiry_ms",
            "review_completed",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn pipeline_stats_json_field_names_stable() {
        let stats = PipelineStats {
            decision_count: 1,
            allow_count: 2,
            deny_count: 3,
            emergency_grants_active: 4,
        };
        let json = serde_json::to_string(&stats).unwrap();
        for field in &[
            "decision_count",
            "allow_count",
            "deny_count",
            "emergency_grants_active",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    // -- Category 6: Display format checks --

    #[test]
    fn pipeline_error_display_flow_already_legal_exact() {
        let err = PipelineError::FlowAlreadyLegal {
            source: Label::Public,
            sink: Label::Internal,
        };
        assert_eq!(
            err.to_string(),
            "flow from public to internal is already lattice-legal"
        );
    }

    #[test]
    fn pipeline_error_display_policy_unavailable_exact() {
        let err = PipelineError::PolicyUnavailable {
            reason: "network timeout".to_string(),
        };
        assert_eq!(err.to_string(), "policy unavailable: network timeout");
    }

    #[test]
    fn pipeline_error_display_no_matching_route_exact() {
        let err = PipelineError::NoMatchingRoute {
            source: Label::Secret,
            sink: Label::Public,
        };
        assert_eq!(
            err.to_string(),
            "no declassification route from secret to public"
        );
    }

    #[test]
    fn pipeline_error_display_loss_exceeds_threshold_exact() {
        let err = PipelineError::LossExceedsThreshold {
            expected_loss_milli: 200_000,
            threshold_milli: 100_000,
        };
        assert_eq!(err.to_string(), "loss 200000 exceeds threshold 100000");
    }

    #[test]
    fn pipeline_error_display_emergency_expired_exact() {
        let err = PipelineError::EmergencyExpired {
            request_id: "req-42".to_string(),
            expiry_ms: 1_700_000_300_000,
        };
        assert_eq!(
            err.to_string(),
            "emergency declassification req-42 expired at 1700000300000"
        );
    }

    #[test]
    fn pipeline_error_display_signing_error_exact() {
        let err = PipelineError::SigningError {
            detail: "invalid key material".to_string(),
        };
        assert_eq!(err.to_string(), "signing error: invalid key material");
    }

    #[test]
    fn pipeline_error_display_validation_error_contains_prefix() {
        let err = PipelineError::ValidationError(IfcValidationError::EmptyClaim {
            claim_id: "c-99".to_string(),
        });
        let s = err.to_string();
        assert!(s.starts_with("validation error:"));
        assert!(s.contains("c-99"));
    }

    // -- Category 7: Hash consistency --

    #[test]
    fn declass_decision_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for decision in &[
            DeclassificationDecision::Allow,
            DeclassificationDecision::Deny,
        ] {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            decision.hash(&mut h1);
            decision.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn ifc_schema_version_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let v = IfcSchemaVersion::CURRENT;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        v.hash(&mut h1);
        v.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn label_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for label in &[
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
            Label::TopSecret,
        ] {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            label.hash(&mut h1);
            label.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    // -- Category 8: Boundary / edge cases --

    #[test]
    fn loss_assessment_zero_loss() {
        let loss = LossAssessment {
            expected_loss_milli: 0,
            data_sensitivity_bps: 0,
            sink_exposure_bps: 0,
            historical_abuse_detected: false,
            summary: String::new(),
        };
        assert!(loss.below_threshold(1));
        assert!(!loss.below_threshold(0)); // 0 < 0 is false
    }

    #[test]
    fn loss_assessment_u64_max() {
        let loss = LossAssessment {
            expected_loss_milli: u64::MAX,
            data_sensitivity_bps: u16::MAX,
            sink_exposure_bps: u16::MAX,
            historical_abuse_detected: true,
            summary: "extreme".to_string(),
        };
        assert!(!loss.below_threshold(u64::MAX)); // u64::MAX < u64::MAX is false
        let json = serde_json::to_string(&loss).unwrap();
        let back: LossAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(loss, back);
    }

    #[test]
    fn emergency_grant_zero_expiry() {
        let grant = EmergencyGrant {
            grant_id: "g".into(),
            request_id: "r".into(),
            extension_id: "ext-test".into(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            decision_contract_id: "decision-contract-test".into(),
            expiry_ms: 0,
            review_completed: false,
        };
        assert!(grant.is_expired(0)); // 0 >= 0 is true
        assert!(grant.is_expired(1));
    }

    #[test]
    fn emergency_grant_u64_max_expiry() {
        let grant = EmergencyGrant {
            grant_id: "g".into(),
            request_id: "r".into(),
            extension_id: "ext-test".into(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            decision_contract_id: "decision-contract-test".into(),
            expiry_ms: u64::MAX,
            review_completed: false,
        };
        assert!(!grant.is_expired(0));
        assert!(!grant.is_expired(u64::MAX - 1));
        assert!(grant.is_expired(u64::MAX)); // equal
    }

    #[test]
    fn request_with_empty_strings() {
        let req = DeclassificationRequest {
            request_id: String::new(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            extension_id: String::new(),
            code_location: String::new(),
            trace_id: String::new(),
            requested_route_id: String::new(),
            decision_contract_id: String::new(),
            is_emergency: false,
            timestamp_ms: 0,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: DeclassificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn request_with_u64_max_timestamp() {
        let req = DeclassificationRequest {
            request_id: "max-ts".into(),
            source_label: Label::Secret,
            sink_clearance: Label::Internal,
            extension_id: "ext".into(),
            code_location: "loc".into(),
            trace_id: "trace".into(),
            requested_route_id: "route".into(),
            decision_contract_id: "decision-contract-max".into(),
            is_emergency: false,
            timestamp_ms: u64::MAX,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: DeclassificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn pipeline_event_none_error_code_roundtrip() {
        let event = PipelineEvent {
            request_id: "r".into(),
            trace_id: "t".into(),
            stage: "s".into(),
            outcome: "o".into(),
            component: "c".into(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: PipelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert!(back.error_code.is_none());
    }

    #[test]
    fn pipeline_event_some_error_code_roundtrip() {
        let event = PipelineEvent {
            request_id: "r".into(),
            trace_id: "t".into(),
            stage: "s".into(),
            outcome: "o".into(),
            component: "c".into(),
            error_code: Some("ERR_99".into()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: PipelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.error_code, back.error_code);
    }

    #[test]
    fn pipeline_config_zero_threshold() {
        let cfg = PipelineConfig {
            loss_threshold_milli: 0,
            emergency_max_duration_ms: 0,
            emit_stage_events: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: PipelineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn pipeline_config_u64_max_values() {
        let cfg = PipelineConfig {
            loss_threshold_milli: u64::MAX,
            emergency_max_duration_ms: u64::MAX,
            emit_stage_events: true,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: PipelineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn pipeline_stats_all_zero() {
        let stats = PipelineStats {
            decision_count: 0,
            allow_count: 0,
            deny_count: 0,
            emergency_grants_active: 0,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: PipelineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    #[test]
    fn pipeline_stats_u64_max_values() {
        let stats = PipelineStats {
            decision_count: u64::MAX,
            allow_count: u64::MAX,
            deny_count: u64::MAX,
            emergency_grants_active: u64::MAX,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: PipelineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    #[test]
    fn custom_label_in_request_roundtrip() {
        let req = DeclassificationRequest {
            request_id: "custom-label-req".into(),
            source_label: Label::Custom {
                name: "project-x".into(),
                level: 10,
            },
            sink_clearance: Label::Public,
            extension_id: "ext".into(),
            code_location: "loc".into(),
            trace_id: "trace".into(),
            requested_route_id: "r".into(),
            decision_contract_id: "decision-contract-custom".into(),
            is_emergency: false,
            timestamp_ms: 100,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: DeclassificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    // -- Category 9: Serde roundtrips (complex structs) --

    #[test]
    fn emergency_grant_reviewed_roundtrip() {
        let grant = EmergencyGrant {
            grant_id: "emg-review".into(),
            request_id: "r-review".into(),
            extension_id: "ext-test".into(),
            source_label: Label::TopSecret,
            sink_clearance: Label::Internal,
            decision_contract_id: "decision-contract-test".into(),
            expiry_ms: u64::MAX,
            review_completed: true,
        };
        let json = serde_json::to_string(&grant).unwrap();
        let back: EmergencyGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, back);
        assert!(back.review_completed);
    }

    #[test]
    fn policy_eval_route_approved_empty_conditions_roundtrip() {
        let r = PolicyEvalResult::RouteApproved {
            route_id: "empty-conds".into(),
            conditions_met: vec![],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: PolicyEvalResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn policy_eval_conditions_not_met_many_conditions_roundtrip() {
        let r = PolicyEvalResult::ConditionsNotMet {
            route_id: "r-many".into(),
            failed_conditions: (0..20).map(|i| format!("cond_{i}")).collect(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: PolicyEvalResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn pipeline_error_validation_serde_all_ifc_variants() {
        let ifc_errors = [
            IfcValidationError::FullClaimHasUncoveredFlows {
                claim_id: "c1".into(),
                uncovered_count: 42,
            },
            IfcValidationError::EmptyClaim {
                claim_id: "c2".into(),
            },
            IfcValidationError::IncompatibleSchema {
                expected: IfcSchemaVersion::CURRENT,
                actual: IfcSchemaVersion {
                    major: 2,
                    minor: 0,
                    patch: 0,
                },
            },
            IfcValidationError::FlowProhibited {
                source: Label::Secret,
                sink: Label::Public,
            },
        ];
        for e in ifc_errors {
            let pe = PipelineError::ValidationError(e);
            let json = serde_json::to_string(&pe).unwrap();
            let back: PipelineError = serde_json::from_str(&json).unwrap();
            assert_eq!(pe, back);
        }
    }

    #[test]
    fn loss_assessment_high_bps_roundtrip() {
        let loss = LossAssessment {
            expected_loss_milli: 1_000_000,
            data_sensitivity_bps: 10_000,
            sink_exposure_bps: 10_000,
            historical_abuse_detected: true,
            summary: "maximum exposure scenario with long description text".to_string(),
        };
        let json = serde_json::to_string(&loss).unwrap();
        let back: LossAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(loss, back);
    }

    // -- Category 10: Debug nonempty --

    #[test]
    fn request_debug_nonempty() {
        let req = make_request("r1", Label::Secret, Label::Internal);
        assert!(!format!("{req:?}").is_empty());
    }

    #[test]
    fn policy_eval_result_debug_nonempty_all() {
        let variants = [
            PolicyEvalResult::RouteApproved {
                route_id: "r".into(),
                conditions_met: vec![],
            },
            PolicyEvalResult::ConditionsNotMet {
                route_id: "r".into(),
                failed_conditions: vec![],
            },
            PolicyEvalResult::NoMatchingRoute,
            PolicyEvalResult::PolicyUnavailable { reason: "x".into() },
        ];
        for v in &variants {
            assert!(!format!("{v:?}").is_empty());
        }
    }

    #[test]
    fn loss_assessment_debug_nonempty() {
        let loss = low_loss();
        assert!(!format!("{loss:?}").is_empty());
    }

    #[test]
    fn pipeline_event_debug_nonempty() {
        let event = PipelineEvent {
            request_id: "r".into(),
            trace_id: "t".into(),
            stage: "s".into(),
            outcome: "o".into(),
            component: "c".into(),
            error_code: None,
        };
        assert!(!format!("{event:?}").is_empty());
    }

    #[test]
    fn pipeline_config_debug_nonempty() {
        let cfg = PipelineConfig::default();
        assert!(!format!("{cfg:?}").is_empty());
    }

    #[test]
    fn emergency_grant_debug_nonempty() {
        let grant = EmergencyGrant {
            grant_id: "g".into(),
            request_id: "r".into(),
            extension_id: "ext-test".into(),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            decision_contract_id: "decision-contract-test".into(),
            expiry_ms: 100,
            review_completed: false,
        };
        assert!(!format!("{grant:?}").is_empty());
    }

    #[test]
    fn pipeline_debug_nonempty() {
        let pipeline = DeclassificationPipeline::default();
        assert!(!format!("{pipeline:?}").is_empty());
    }

    #[test]
    fn pipeline_stats_debug_nonempty() {
        let stats = PipelineStats {
            decision_count: 0,
            allow_count: 0,
            deny_count: 0,
            emergency_grants_active: 0,
        };
        assert!(!format!("{stats:?}").is_empty());
    }

    #[test]
    fn pipeline_error_debug_nonempty_all() {
        let variants: [PipelineError; 7] = [
            PipelineError::FlowAlreadyLegal {
                source: Label::Public,
                sink: Label::Internal,
            },
            PipelineError::PolicyUnavailable { reason: "x".into() },
            PipelineError::NoMatchingRoute {
                source: Label::Secret,
                sink: Label::Public,
            },
            PipelineError::LossExceedsThreshold {
                expected_loss_milli: 1,
                threshold_milli: 0,
            },
            PipelineError::EmergencyExpired {
                request_id: "r".into(),
                expiry_ms: 0,
            },
            PipelineError::SigningError { detail: "d".into() },
            PipelineError::ValidationError(IfcValidationError::EmptyClaim {
                claim_id: "c".into(),
            }),
        ];
        for v in &variants {
            assert!(!format!("{v:?}").is_empty());
        }
    }

    // -- Additional functional / edge-case enrichment --

    #[test]
    fn emergency_pathway_with_mismatched_extension() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("nonexistent", Label::Secret, Label::Public);
        request.extension_id = "wrong-ext".to_string();
        request.is_emergency = true;

        // Extension mismatch => PolicyUnavailable, but emergency still fires
        let result = pipeline.process(&request, &policy, &low_loss(), &test_key());
        // Emergency pathway should bypass the PolicyUnavailable error
        let receipt = result.unwrap();
        assert_eq!(receipt.decision, DeclassificationDecision::Allow);
    }

    #[test]
    fn multiple_emergency_grants_tracked() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let key = test_key();

        for i in 0..3 {
            let mut req = make_request(&format!("bad-route-{i}"), Label::Secret, Label::Public);
            req.request_id = format!("req-emg-{i}");
            req.is_emergency = true;
            pipeline.process(&req, &policy, &low_loss(), &key).unwrap();
        }

        let stats = pipeline.stats();
        assert_eq!(stats.emergency_grants_active, 3);
        assert_eq!(stats.allow_count, 3);
    }

    #[test]
    fn deny_receipt_stored_in_pipeline() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &high_loss(), &test_key())
            .unwrap();
        assert_eq!(receipt.decision, DeclassificationDecision::Deny);
        assert_eq!(pipeline.receipts().len(), 1);
        assert_eq!(
            pipeline.receipts()[0].decision,
            DeclassificationDecision::Deny
        );
    }

    #[test]
    fn emergency_grant_expiry_uses_config_duration() {
        let config = PipelineConfig {
            emergency_max_duration_ms: 60_000,
            ..PipelineConfig::default()
        };
        let mut pipeline = DeclassificationPipeline::new(config);
        let policy = make_policy();
        let mut request = make_request("bad-route", Label::Secret, Label::Public);
        request.is_emergency = true;
        request.timestamp_ms = 1_000_000;

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        // Grant should be active at timestamp + 59_999
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Public,
                    &request.decision_contract_id,
                    1_059_999,
                )
                .is_some()
        );
        // Grant should be expired at timestamp + 60_000
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Public,
                    &request.decision_contract_id,
                    1_060_000,
                )
                .is_none()
        );
    }

    #[test]
    fn check_emergency_grant_wrong_labels_returns_none() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let mut request = make_request("bad-route", Label::Secret, Label::Public);
        request.is_emergency = true;

        pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();

        // Correct labels find the grant
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Public,
                    &request.decision_contract_id,
                    request.timestamp_ms,
                )
                .is_some()
        );
        // Wrong source label
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Internal,
                    &Label::Public,
                    &request.decision_contract_id,
                    request.timestamp_ms,
                )
                .is_none()
        );
        // Wrong sink label
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Internal,
                    &request.decision_contract_id,
                    request.timestamp_ms,
                )
                .is_none()
        );
        // Wrong extension or decision contract should not reuse the grant.
        assert!(
            pipeline
                .check_emergency_grant(
                    "other-ext",
                    &Label::Secret,
                    &Label::Public,
                    &request.decision_contract_id,
                    request.timestamp_ms,
                )
                .is_none()
        );
        assert!(
            pipeline
                .check_emergency_grant(
                    &request.extension_id,
                    &Label::Secret,
                    &Label::Public,
                    "other-contract",
                    request.timestamp_ms,
                )
                .is_none()
        );
    }

    #[test]
    fn conf_public_route_produces_correct_receipt() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-conf-public", Label::Confidential, Label::Public);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert_eq!(receipt.decision, DeclassificationDecision::Allow);
        assert_eq!(receipt.source_label, Label::Confidential);
        assert_eq!(receipt.sink_clearance, Label::Public);
        assert_eq!(receipt.declassification_route_ref, "declass-conf-public");
    }

    #[test]
    fn receipt_id_prefixed_with_rcpt() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert!(
            receipt.receipt_id.starts_with("rcpt-"),
            "receipt_id should start with 'rcpt-'"
        );
    }

    #[test]
    fn receipt_timestamp_matches_request() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let receipt = pipeline
            .process(&request, &policy, &low_loss(), &test_key())
            .unwrap();
        assert_eq!(receipt.timestamp_ms, request.timestamp_ms);
    }

    #[test]
    fn receipt_loss_assessment_matches_input() {
        let mut pipeline = DeclassificationPipeline::default();
        let policy = make_policy();
        let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        let loss = low_loss();
        let receipt = pipeline
            .process(&request, &policy, &loss, &test_key())
            .unwrap();
        assert_eq!(receipt.loss_assessment_milli, loss.expected_loss_milli);
    }
}
