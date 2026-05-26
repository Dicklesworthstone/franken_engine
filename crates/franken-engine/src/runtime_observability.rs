//! Runtime security observability surface.
//!
//! This module defines the counters/gauge and structured log schema for
//! security-critical runtime failures:
//! - authentication failures
//! - capability denials
//! - replay drops
//! - checkpoint violations
//! - revocation freshness/revocation checks
//! - cross-zone reference decisions
//!
//! # Wiring status (honest accounting — see `bd-unc29`)
//!
//! These are not all fed by the runtime yet. The schema and counters exist as
//! a complete surface, but only the sites below currently call into it:
//! - **capability denials** — WIRED. The live capability gate in
//!   `baseline_interpreter::check_hostcall_capability_gate` calls
//!   [`RuntimeSecurityObservability::record_capability_denial`] on every real
//!   denial, so `capability_denial_total` and the structured security log
//!   reflect actual runtime denials (exposed via
//!   `InterpreterCore::security_metrics` / `security_observability`).
//! - **authentication failures** — WIRED. The Merkle-signed evidence-envelope
//!   verification path in `session_signing_batch` exposes
//!   `MerkleSignedEnvelope::verify_observed` / `verify_with_key_observed`, which
//!   call [`RuntimeSecurityObservability::record_auth_failure`] on every real
//!   verification failure (signature, root, inclusion-proof, or key mismatch),
//!   classified fail-closed as [`AuthFailureType::SignatureInvalid`]. Tracked
//!   under `bd-x92qq` (follow-up to `bd-unc29`).
//! - **replay drops, checkpoint violations, revocation checks, cross-zone
//!   references** — NOT YET WIRED. These `record_*` methods are presently
//!   invoked only from this module's tests. Their real failure sites (an
//!   anti-replay session-sequence guard — note `ReplayDropReason` is
//!   `{DuplicateSeq, StaleSeq, CrossSession}`, i.e. message-sequence dedup, not
//!   `deterministic_replay::ReplayEngine` divergence — checkpoint enforcement,
//!   revocation freshness checks, and cross-zone reference decisions) must
//!   still be wired before the counters reflect production events. Tracked as
//!   `bd-x92qq` (follow-up to `bd-unc29`).
//!
//! Note: capability denials also remain observable through the interpreter's
//! `WitnessEventKind::CapabilityChecked` witness stream; this surface adds the
//! typed, Prometheus-exportable counter and redaction-safe structured log.
//!
//! Plan reference: Section 10.10 item 22 (`bd-3s6`).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error_code::FrankenErrorCode;

pub const AUTH_FAILURE_TOTAL: &str = "auth_failure_total";
pub const CAPABILITY_DENIAL_TOTAL: &str = "capability_denial_total";
pub const REPLAY_DROP_TOTAL: &str = "replay_drop_total";
pub const CHECKPOINT_VIOLATION_TOTAL: &str = "checkpoint_violation_total";
pub const REVOCATION_FRESHNESS_DEGRADED_SECONDS: &str = "revocation_freshness_degraded_seconds";
pub const REVOCATION_CHECK_TOTAL: &str = "revocation_check_total";
pub const CROSS_ZONE_REFERENCE_TOTAL: &str = "cross_zone_reference_total";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailureType {
    SignatureInvalid,
    KeyExpired,
    KeyRevoked,
    AttestationInvalid,
}

impl AuthFailureType {
    pub const ALL: [Self; 4] = [
        Self::SignatureInvalid,
        Self::KeyExpired,
        Self::KeyRevoked,
        Self::AttestationInvalid,
    ];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::SignatureInvalid => "signature_invalid",
            Self::KeyExpired => "key_expired",
            Self::KeyRevoked => "key_revoked",
            Self::AttestationInvalid => "attestation_invalid",
        }
    }
}

impl fmt::Display for AuthFailureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDenialReason {
    InsufficientAuthority,
    CeilingExceeded,
    AttenuationViolation,
    AudienceMismatch,
    Expired,
    NotYetValid,
}

impl CapabilityDenialReason {
    pub const ALL: [Self; 6] = [
        Self::InsufficientAuthority,
        Self::CeilingExceeded,
        Self::AttenuationViolation,
        Self::AudienceMismatch,
        Self::Expired,
        Self::NotYetValid,
    ];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::InsufficientAuthority => "insufficient_authority",
            Self::CeilingExceeded => "ceiling_exceeded",
            Self::AttenuationViolation => "attenuation_violation",
            Self::AudienceMismatch => "audience_mismatch",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
        }
    }
}

impl fmt::Display for CapabilityDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDropReason {
    DuplicateSeq,
    StaleSeq,
    CrossSession,
}

impl ReplayDropReason {
    pub const ALL: [Self; 3] = [Self::DuplicateSeq, Self::StaleSeq, Self::CrossSession];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::DuplicateSeq => "duplicate_seq",
            Self::StaleSeq => "stale_seq",
            Self::CrossSession => "cross_session",
        }
    }
}

impl fmt::Display for ReplayDropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointViolationType {
    RollbackAttempt,
    ForkDetected,
    QuorumInsufficient,
}

impl CheckpointViolationType {
    pub const ALL: [Self; 3] = [
        Self::RollbackAttempt,
        Self::ForkDetected,
        Self::QuorumInsufficient,
    ];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::RollbackAttempt => "rollback_attempt",
            Self::ForkDetected => "fork_detected",
            Self::QuorumInsufficient => "quorum_insufficient",
        }
    }
}

impl fmt::Display for CheckpointViolationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationCheckOutcome {
    Pass,
    Revoked,
    Stale,
}

impl RevocationCheckOutcome {
    pub const ALL: [Self; 3] = [Self::Pass, Self::Revoked, Self::Stale];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Revoked => "revoked",
            Self::Stale => "stale",
        }
    }
}

impl fmt::Display for RevocationCheckOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossZoneReferenceType {
    ProvenanceAllowed,
    AuthorityDenied,
}

impl CrossZoneReferenceType {
    pub const ALL: [Self; 2] = [Self::ProvenanceAllowed, Self::AuthorityDenied];

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ProvenanceAllowed => "provenance_allowed",
            Self::AuthorityDenied => "authority_denied",
        }
    }
}

impl fmt::Display for CrossZoneReferenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    AuthFailure,
    CapabilityDenial,
    ReplayDrop,
    CheckpointViolation,
    RevocationCheck,
    CrossZoneReference,
}

impl SecurityEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthFailure => "auth_failure",
            Self::CapabilityDenial => "capability_denial",
            Self::ReplayDrop => "replay_drop",
            Self::CheckpointViolation => "checkpoint_violation",
            Self::RevocationCheck => "revocation_check",
            Self::CrossZoneReference => "cross_zone_reference",
        }
    }
}

impl fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityOutcome {
    Pass,
    Allowed,
    Denied,
    Dropped,
    Rejected,
    Degraded,
}

impl SecurityOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Dropped => "dropped",
            Self::Rejected => "rejected",
            Self::Degraded => "degraded",
        }
    }
}

impl fmt::Display for SecurityOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventContext {
    pub timestamp_ns: u64,
    pub trace_id: String,
    pub principal_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub zone_id: String,
    pub component: String,
}

impl SecurityEventContext {
    fn sanitized(self) -> Self {
        Self {
            timestamp_ns: self.timestamp_ns,
            trace_id: sanitize_required(&self.trace_id, "trace-missing"),
            principal_id: sanitize_required(&self.principal_id, "principal-missing"),
            decision_id: sanitize_required(&self.decision_id, "decision-missing"),
            policy_id: sanitize_required(&self.policy_id, "policy-missing"),
            zone_id: sanitize_required(&self.zone_id, "zone-missing"),
            component: sanitize_required(&self.component, "runtime_observability"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredSecurityLogEvent {
    pub timestamp_ns: u64,
    pub trace_id: String,
    pub component: String,
    pub event_type: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub principal_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub zone_id: String,
    pub metadata: BTreeMap<String, String>,
}

impl StructuredSecurityLogEvent {
    pub fn required_fields_present(&self) -> bool {
        !self.trace_id.is_empty()
            && !self.component.is_empty()
            && !self.event_type.is_empty()
            && !self.outcome.is_empty()
            && !self.principal_id.is_empty()
            && !self.decision_id.is_empty()
            && !self.policy_id.is_empty()
            && !self.zone_id.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSecurityMetrics {
    pub auth_failure_total: BTreeMap<AuthFailureType, u64>,
    pub capability_denial_total: BTreeMap<CapabilityDenialReason, u64>,
    pub replay_drop_total: BTreeMap<ReplayDropReason, u64>,
    pub checkpoint_violation_total: BTreeMap<CheckpointViolationType, u64>,
    pub revocation_freshness_degraded_seconds: u64,
    pub revocation_check_total: BTreeMap<RevocationCheckOutcome, u64>,
    pub cross_zone_reference_total: BTreeMap<CrossZoneReferenceType, u64>,
}

impl Default for RuntimeSecurityMetrics {
    fn default() -> Self {
        Self {
            auth_failure_total: zeroed_metric_map(&AuthFailureType::ALL),
            capability_denial_total: zeroed_metric_map(&CapabilityDenialReason::ALL),
            replay_drop_total: zeroed_metric_map(&ReplayDropReason::ALL),
            checkpoint_violation_total: zeroed_metric_map(&CheckpointViolationType::ALL),
            revocation_freshness_degraded_seconds: 0,
            revocation_check_total: zeroed_metric_map(&RevocationCheckOutcome::ALL),
            cross_zone_reference_total: zeroed_metric_map(&CrossZoneReferenceType::ALL),
        }
    }
}

impl RuntimeSecurityMetrics {
    pub fn to_prometheus(&self) -> String {
        let mut lines = Vec::new();
        lines.push("# HELP auth_failure_total Authentication failures by type.".to_string());
        lines.push("# TYPE auth_failure_total counter".to_string());
        for label in AuthFailureType::ALL {
            let value = self.auth_failure_total.get(&label).copied().unwrap_or(0);
            lines.push(format!(
                "auth_failure_total{{type=\"{}\"}} {}",
                label.as_label(),
                value
            ));
        }

        lines.push("# HELP capability_denial_total Capability denials by reason.".to_string());
        lines.push("# TYPE capability_denial_total counter".to_string());
        for label in CapabilityDenialReason::ALL {
            let value = self
                .capability_denial_total
                .get(&label)
                .copied()
                .unwrap_or(0);
            lines.push(format!(
                "capability_denial_total{{reason=\"{}\"}} {}",
                label.as_label(),
                value
            ));
        }

        lines.push("# HELP replay_drop_total Replay drops by reason.".to_string());
        lines.push("# TYPE replay_drop_total counter".to_string());
        for label in ReplayDropReason::ALL {
            let value = self.replay_drop_total.get(&label).copied().unwrap_or(0);
            lines.push(format!(
                "replay_drop_total{{reason=\"{}\"}} {}",
                label.as_label(),
                value
            ));
        }

        lines.push("# HELP checkpoint_violation_total Checkpoint violations by type.".to_string());
        lines.push("# TYPE checkpoint_violation_total counter".to_string());
        for label in CheckpointViolationType::ALL {
            let value = self
                .checkpoint_violation_total
                .get(&label)
                .copied()
                .unwrap_or(0);
            lines.push(format!(
                "checkpoint_violation_total{{type=\"{}\"}} {}",
                label.as_label(),
                value
            ));
        }

        lines.push(
            "# HELP revocation_freshness_degraded_seconds Time spent in revocation-degraded mode."
                .to_string(),
        );
        lines.push("# TYPE revocation_freshness_degraded_seconds gauge".to_string());
        lines.push(format!(
            "revocation_freshness_degraded_seconds {}",
            self.revocation_freshness_degraded_seconds
        ));

        lines.push("# HELP revocation_check_total Revocation checks by outcome.".to_string());
        lines.push("# TYPE revocation_check_total counter".to_string());
        for label in RevocationCheckOutcome::ALL {
            let value = self
                .revocation_check_total
                .get(&label)
                .copied()
                .unwrap_or(0);
            lines.push(format!(
                "revocation_check_total{{outcome=\"{}\"}} {}",
                label.as_label(),
                value
            ));
        }

        lines.push("# HELP cross_zone_reference_total Cross-zone references by type.".to_string());
        lines.push("# TYPE cross_zone_reference_total counter".to_string());
        for label in CrossZoneReferenceType::ALL {
            let value = self
                .cross_zone_reference_total
                .get(&label)
                .copied()
                .unwrap_or(0);
            lines.push(format!(
                "cross_zone_reference_total{{type=\"{}\"}} {}",
                label.as_label(),
                value
            ));
        }

        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeSecurityObservability {
    pub metrics: RuntimeSecurityMetrics,
    pub logs: Vec<StructuredSecurityLogEvent>,
}

impl RuntimeSecurityObservability {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn metrics(&self) -> &RuntimeSecurityMetrics {
        &self.metrics
    }

    pub fn logs(&self) -> &[StructuredSecurityLogEvent] {
        &self.logs
    }

    pub fn export_prometheus_metrics(&self) -> String {
        self.metrics.to_prometheus()
    }

    pub fn export_logs_jsonl(&self) -> String {
        render_security_logs_jsonl(&self.logs)
    }

    pub fn record_auth_failure(
        &mut self,
        context: SecurityEventContext,
        failure_type: AuthFailureType,
        key_material: Option<&str>,
        token_content: Option<&str>,
    ) -> StructuredSecurityLogEvent {
        let mut metadata = BTreeMap::new();
        metadata.insert("failure_type".to_string(), failure_type.to_string());
        if let Some(value) = key_material {
            metadata.insert(
                "key_material_hash".to_string(),
                redact_sensitive_value(value),
            );
        }
        if let Some(value) = token_content {
            metadata.insert(
                "token_content_hash".to_string(),
                redact_sensitive_value(value),
            );
        }

        let event = build_event(
            context,
            SecurityEventType::AuthFailure,
            SecurityOutcome::Denied,
            Some(auth_error_code(failure_type).stable_code()),
            metadata,
        );
        self.record_event(event, |metrics| {
            increment_enum_counter(&mut metrics.auth_failure_total, failure_type)
        })
    }

    pub fn record_capability_denial(
        &mut self,
        context: SecurityEventContext,
        reason: CapabilityDenialReason,
        requested_capability: &str,
    ) -> StructuredSecurityLogEvent {
        let mut metadata = BTreeMap::new();
        metadata.insert("denial_reason".to_string(), reason.to_string());
        metadata.insert(
            "requested_capability".to_string(),
            sanitize_required(requested_capability, "unspecified"),
        );

        let event = build_event(
            context,
            SecurityEventType::CapabilityDenial,
            SecurityOutcome::Denied,
            Some(capability_error_code(reason).stable_code()),
            metadata,
        );
        self.record_event(event, |metrics| {
            increment_enum_counter(&mut metrics.capability_denial_total, reason);
        })
    }

    pub fn record_replay_drop(
        &mut self,
        context: SecurityEventContext,
        reason: ReplayDropReason,
        received_seq: u64,
        expected_seq: u64,
        session_id: &str,
    ) -> StructuredSecurityLogEvent {
        let mut metadata = BTreeMap::new();
        metadata.insert("drop_reason".to_string(), reason.to_string());
        metadata.insert("received_seq".to_string(), received_seq.to_string());
        metadata.insert("expected_seq".to_string(), expected_seq.to_string());
        metadata.insert(
            "session_id_hash".to_string(),
            redact_sensitive_value(session_id),
        );

        let event = build_event(
            context,
            SecurityEventType::ReplayDrop,
            SecurityOutcome::Dropped,
            Some(replay_error_code(reason).stable_code()),
            metadata,
        );
        self.record_event(event, |metrics| {
            increment_enum_counter(&mut metrics.replay_drop_total, reason)
        })
    }

    pub fn record_checkpoint_violation(
        &mut self,
        context: SecurityEventContext,
        violation: CheckpointViolationType,
        attempted_seq: u64,
        current_seq: u64,
    ) -> StructuredSecurityLogEvent {
        let mut metadata = BTreeMap::new();
        metadata.insert("violation_type".to_string(), violation.to_string());
        metadata.insert("attempted_seq".to_string(), attempted_seq.to_string());
        metadata.insert("current_seq".to_string(), current_seq.to_string());

        let event = build_event(
            context,
            SecurityEventType::CheckpointViolation,
            SecurityOutcome::Rejected,
            Some(checkpoint_error_code(violation).stable_code()),
            metadata,
        );
        self.record_event(event, |metrics| {
            increment_enum_counter(&mut metrics.checkpoint_violation_total, violation);
        })
    }

    pub fn record_revocation_check(
        &mut self,
        context: SecurityEventContext,
        outcome: RevocationCheckOutcome,
        local_head_seq: u64,
        expected_head_seq: u64,
        threshold: u64,
        degraded_seconds: Option<u64>,
    ) -> StructuredSecurityLogEvent {
        let staleness_gap = expected_head_seq.saturating_sub(local_head_seq);
        let mut metadata = BTreeMap::new();
        metadata.insert("revocation_outcome".to_string(), outcome.to_string());
        metadata.insert("local_head_seq".to_string(), local_head_seq.to_string());
        metadata.insert(
            "expected_head_seq".to_string(),
            expected_head_seq.to_string(),
        );
        metadata.insert("staleness_gap".to_string(), staleness_gap.to_string());
        metadata.insert("threshold".to_string(), threshold.to_string());

        let security_outcome = match outcome {
            RevocationCheckOutcome::Pass => SecurityOutcome::Pass,
            RevocationCheckOutcome::Revoked => SecurityOutcome::Denied,
            RevocationCheckOutcome::Stale => SecurityOutcome::Degraded,
        };

        let error_code = match outcome {
            RevocationCheckOutcome::Pass => None,
            RevocationCheckOutcome::Revoked | RevocationCheckOutcome::Stale => {
                Some(revocation_error_code(outcome).stable_code())
            }
        };

        if let Some(seconds) = degraded_seconds {
            metadata.insert("degraded_seconds".to_string(), seconds.to_string());
        }

        let event = build_event(
            context,
            SecurityEventType::RevocationCheck,
            security_outcome,
            error_code,
            metadata,
        );

        self.record_event(event, |metrics| {
            increment_enum_counter(&mut metrics.revocation_check_total, outcome);
            if outcome == RevocationCheckOutcome::Stale {
                metrics.revocation_freshness_degraded_seconds = degraded_seconds.unwrap_or(0);
            }
        })
    }

    pub fn record_cross_zone_reference(
        &mut self,
        context: SecurityEventContext,
        reference_type: CrossZoneReferenceType,
        source_zone: &str,
        target_zone: &str,
    ) -> StructuredSecurityLogEvent {
        let mut metadata = BTreeMap::new();
        metadata.insert("reference_type".to_string(), reference_type.to_string());
        metadata.insert(
            "source_zone".to_string(),
            sanitize_required(source_zone, "source-zone-missing"),
        );
        metadata.insert(
            "target_zone".to_string(),
            sanitize_required(target_zone, "target-zone-missing"),
        );

        let (outcome, error_code) = match reference_type {
            CrossZoneReferenceType::ProvenanceAllowed => (SecurityOutcome::Allowed, None),
            CrossZoneReferenceType::AuthorityDenied => (
                SecurityOutcome::Denied,
                Some(cross_zone_error_code(reference_type).stable_code()),
            ),
        };

        let event = build_event(
            context,
            SecurityEventType::CrossZoneReference,
            outcome,
            error_code,
            metadata,
        );
        self.record_event(event, |metrics| {
            increment_enum_counter(&mut metrics.cross_zone_reference_total, reference_type);
        })
    }

    fn record_event<F>(
        &mut self,
        event: StructuredSecurityLogEvent,
        mutate_metrics: F,
    ) -> StructuredSecurityLogEvent
    where
        F: FnOnce(&mut RuntimeSecurityMetrics),
    {
        mutate_metrics(&mut self.metrics);
        self.logs.push(event.clone());
        event
    }
}

pub fn render_security_logs_jsonl(events: &[StructuredSecurityLogEvent]) -> String {
    let mut lines = Vec::with_capacity(events.len());
    for event in events {
        lines.push(serde_json::to_string(event).expect("serialize derived Serialize"));
    }
    lines.join("\n")
}

pub fn parse_security_logs_jsonl(input: &str) -> Result<Vec<StructuredSecurityLogEvent>, String> {
    let mut events = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<StructuredSecurityLogEvent>(line)
            .map_err(|error| format!("failed to parse JSONL line {}: {error}", idx + 1))?;
        events.push(event);
    }
    Ok(events)
}

pub fn redact_sensitive_value(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn build_event(
    context: SecurityEventContext,
    event_type: SecurityEventType,
    outcome: SecurityOutcome,
    error_code: Option<String>,
    metadata: BTreeMap<String, String>,
) -> StructuredSecurityLogEvent {
    let context = context.sanitized();
    StructuredSecurityLogEvent {
        timestamp_ns: context.timestamp_ns,
        trace_id: context.trace_id,
        component: context.component,
        event_type: event_type.to_string(),
        outcome: outcome.to_string(),
        error_code,
        principal_id: context.principal_id,
        decision_id: context.decision_id,
        policy_id: context.policy_id,
        zone_id: context.zone_id,
        metadata,
    }
}

fn sanitize_required(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn zeroed_metric_map<K>(values: &[K]) -> BTreeMap<K, u64>
where
    K: Copy + Ord,
{
    values.iter().copied().map(|value| (value, 0)).collect()
}

fn increment_enum_counter<K>(counter: &mut BTreeMap<K, u64>, key: K)
where
    K: Copy + Ord,
{
    *counter.entry(key).or_insert(0) += 1;
}

fn auth_error_code(reason: AuthFailureType) -> FrankenErrorCode {
    match reason {
        AuthFailureType::SignatureInvalid => FrankenErrorCode::SignatureVerificationError,
        AuthFailureType::KeyExpired => FrankenErrorCode::EpochWindowValidationError,
        AuthFailureType::KeyRevoked => FrankenErrorCode::RevocationChainIntegrityError,
        AuthFailureType::AttestationInvalid => FrankenErrorCode::MultiSigVerificationError,
    }
}

fn capability_error_code(reason: CapabilityDenialReason) -> FrankenErrorCode {
    match reason {
        CapabilityDenialReason::InsufficientAuthority => FrankenErrorCode::CapabilityDeniedError,
        CapabilityDenialReason::CeilingExceeded => FrankenErrorCode::CapabilityDeniedError,
        CapabilityDenialReason::AttenuationViolation => {
            FrankenErrorCode::CapabilityTokenValidationError
        }
        CapabilityDenialReason::AudienceMismatch => {
            FrankenErrorCode::CapabilityTokenValidationError
        }
        CapabilityDenialReason::Expired => FrankenErrorCode::CapabilityTokenValidationError,
        CapabilityDenialReason::NotYetValid => FrankenErrorCode::CapabilityTokenValidationError,
    }
}

fn replay_error_code(reason: ReplayDropReason) -> FrankenErrorCode {
    match reason {
        ReplayDropReason::DuplicateSeq
        | ReplayDropReason::StaleSeq
        | ReplayDropReason::CrossSession => FrankenErrorCode::IdempotencyWorkflowError,
    }
}

fn checkpoint_error_code(violation: CheckpointViolationType) -> FrankenErrorCode {
    match violation {
        CheckpointViolationType::RollbackAttempt => {
            FrankenErrorCode::CheckpointFrontierEnforcementError
        }
        CheckpointViolationType::ForkDetected => FrankenErrorCode::ForkDetectionError,
        CheckpointViolationType::QuorumInsufficient => {
            FrankenErrorCode::PolicyCheckpointValidationError
        }
    }
}

fn revocation_error_code(outcome: RevocationCheckOutcome) -> FrankenErrorCode {
    match outcome {
        RevocationCheckOutcome::Pass => FrankenErrorCode::RevocationChainIntegrityError,
        RevocationCheckOutcome::Revoked => FrankenErrorCode::RevocationChainIntegrityError,
        RevocationCheckOutcome::Stale => FrankenErrorCode::RevocationChainIntegrityError,
    }
}

fn cross_zone_error_code(reference_type: CrossZoneReferenceType) -> FrankenErrorCode {
    match reference_type {
        CrossZoneReferenceType::ProvenanceAllowed => FrankenErrorCode::SlotRegistryAuthorityError,
        CrossZoneReferenceType::AuthorityDenied => FrankenErrorCode::SlotRegistryAuthorityError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> SecurityEventContext {
        SecurityEventContext {
            timestamp_ns: 1_000_000,
            trace_id: "trace-001".to_string(),
            principal_id: "principal-001".to_string(),
            decision_id: "decision-001".to_string(),
            policy_id: "policy-001".to_string(),
            zone_id: "zone-001".to_string(),
            component: "test_component".to_string(),
        }
    }

    // ── AuthFailureType ───────────────────────────────────────────────

    #[test]
    fn auth_failure_type_as_label() {
        assert_eq!(
            AuthFailureType::SignatureInvalid.as_label(),
            "signature_invalid"
        );
        assert_eq!(AuthFailureType::KeyExpired.as_label(), "key_expired");
        assert_eq!(AuthFailureType::KeyRevoked.as_label(), "key_revoked");
        assert_eq!(
            AuthFailureType::AttestationInvalid.as_label(),
            "attestation_invalid"
        );
    }

    #[test]
    fn auth_failure_type_display() {
        assert_eq!(
            AuthFailureType::SignatureInvalid.to_string(),
            "signature_invalid"
        );
    }

    #[test]
    fn auth_failure_type_all_constant() {
        assert_eq!(AuthFailureType::ALL.len(), 4);
    }

    #[test]
    fn auth_failure_type_serde_round_trip() {
        for t in AuthFailureType::ALL {
            let json = serde_json::to_string(&t).expect("serialize derived Serialize");
            let back: AuthFailureType =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, t);
        }
    }

    // ── CapabilityDenialReason ─────────────────────────────────────────

    #[test]
    fn capability_denial_reason_as_label() {
        assert_eq!(
            CapabilityDenialReason::InsufficientAuthority.as_label(),
            "insufficient_authority"
        );
        assert_eq!(
            CapabilityDenialReason::CeilingExceeded.as_label(),
            "ceiling_exceeded"
        );
        assert_eq!(
            CapabilityDenialReason::AttenuationViolation.as_label(),
            "attenuation_violation"
        );
        assert_eq!(
            CapabilityDenialReason::AudienceMismatch.as_label(),
            "audience_mismatch"
        );
        assert_eq!(CapabilityDenialReason::Expired.as_label(), "expired");
        assert_eq!(
            CapabilityDenialReason::NotYetValid.as_label(),
            "not_yet_valid"
        );
    }

    #[test]
    fn capability_denial_reason_all_constant() {
        assert_eq!(CapabilityDenialReason::ALL.len(), 6);
    }

    #[test]
    fn capability_denial_reason_serde_round_trip() {
        for r in CapabilityDenialReason::ALL {
            let json = serde_json::to_string(&r).expect("serialize derived Serialize");
            let back: CapabilityDenialReason =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, r);
        }
    }

    // ── ReplayDropReason ──────────────────────────────────────────────

    #[test]
    fn replay_drop_reason_as_label() {
        assert_eq!(ReplayDropReason::DuplicateSeq.as_label(), "duplicate_seq");
        assert_eq!(ReplayDropReason::StaleSeq.as_label(), "stale_seq");
        assert_eq!(ReplayDropReason::CrossSession.as_label(), "cross_session");
    }

    #[test]
    fn replay_drop_reason_all_constant() {
        assert_eq!(ReplayDropReason::ALL.len(), 3);
    }

    #[test]
    fn replay_drop_reason_serde_round_trip() {
        for r in ReplayDropReason::ALL {
            let json = serde_json::to_string(&r).expect("serialize derived Serialize");
            let back: ReplayDropReason =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, r);
        }
    }

    // ── CheckpointViolationType ───────────────────────────────────────

    #[test]
    fn checkpoint_violation_as_label() {
        assert_eq!(
            CheckpointViolationType::RollbackAttempt.as_label(),
            "rollback_attempt"
        );
        assert_eq!(
            CheckpointViolationType::ForkDetected.as_label(),
            "fork_detected"
        );
        assert_eq!(
            CheckpointViolationType::QuorumInsufficient.as_label(),
            "quorum_insufficient"
        );
    }

    #[test]
    fn checkpoint_violation_all_constant() {
        assert_eq!(CheckpointViolationType::ALL.len(), 3);
    }

    #[test]
    fn checkpoint_violation_serde_round_trip() {
        for v in CheckpointViolationType::ALL {
            let json = serde_json::to_string(&v).expect("serialize derived Serialize");
            let back: CheckpointViolationType =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, v);
        }
    }

    // ── RevocationCheckOutcome ────────────────────────────────────────

    #[test]
    fn revocation_check_outcome_as_label() {
        assert_eq!(RevocationCheckOutcome::Pass.as_label(), "pass");
        assert_eq!(RevocationCheckOutcome::Revoked.as_label(), "revoked");
        assert_eq!(RevocationCheckOutcome::Stale.as_label(), "stale");
    }

    #[test]
    fn revocation_check_outcome_all_constant() {
        assert_eq!(RevocationCheckOutcome::ALL.len(), 3);
    }

    #[test]
    fn revocation_check_outcome_serde_round_trip() {
        for o in RevocationCheckOutcome::ALL {
            let json = serde_json::to_string(&o).expect("serialize derived Serialize");
            let back: RevocationCheckOutcome =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, o);
        }
    }

    // ── CrossZoneReferenceType ────────────────────────────────────────

    #[test]
    fn cross_zone_reference_type_as_label() {
        assert_eq!(
            CrossZoneReferenceType::ProvenanceAllowed.as_label(),
            "provenance_allowed"
        );
        assert_eq!(
            CrossZoneReferenceType::AuthorityDenied.as_label(),
            "authority_denied"
        );
    }

    #[test]
    fn cross_zone_reference_type_all_constant() {
        assert_eq!(CrossZoneReferenceType::ALL.len(), 2);
    }

    #[test]
    fn cross_zone_reference_type_serde_round_trip() {
        for t in CrossZoneReferenceType::ALL {
            let json = serde_json::to_string(&t).expect("serialize derived Serialize");
            let back: CrossZoneReferenceType =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, t);
        }
    }

    // ── SecurityEventType ─────────────────────────────────────────────

    #[test]
    fn security_event_type_as_str() {
        assert_eq!(SecurityEventType::AuthFailure.as_str(), "auth_failure");
        assert_eq!(
            SecurityEventType::CapabilityDenial.as_str(),
            "capability_denial"
        );
        assert_eq!(SecurityEventType::ReplayDrop.as_str(), "replay_drop");
        assert_eq!(
            SecurityEventType::CheckpointViolation.as_str(),
            "checkpoint_violation"
        );
        assert_eq!(
            SecurityEventType::RevocationCheck.as_str(),
            "revocation_check"
        );
        assert_eq!(
            SecurityEventType::CrossZoneReference.as_str(),
            "cross_zone_reference"
        );
    }

    #[test]
    fn security_event_type_display() {
        assert_eq!(SecurityEventType::AuthFailure.to_string(), "auth_failure");
    }

    // ── SecurityOutcome ───────────────────────────────────────────────

    #[test]
    fn security_outcome_as_str() {
        assert_eq!(SecurityOutcome::Pass.as_str(), "pass");
        assert_eq!(SecurityOutcome::Allowed.as_str(), "allowed");
        assert_eq!(SecurityOutcome::Denied.as_str(), "denied");
        assert_eq!(SecurityOutcome::Dropped.as_str(), "dropped");
        assert_eq!(SecurityOutcome::Rejected.as_str(), "rejected");
        assert_eq!(SecurityOutcome::Degraded.as_str(), "degraded");
    }

    // ── SecurityEventContext::sanitized ────────────────────────────────

    #[test]
    fn context_sanitized_preserves_values() {
        let ctx = test_context().sanitized();
        assert_eq!(ctx.trace_id, "trace-001");
        assert_eq!(ctx.principal_id, "principal-001");
    }

    #[test]
    fn context_sanitized_fills_empty_with_fallback() {
        let ctx = SecurityEventContext {
            timestamp_ns: 0,
            trace_id: "".to_string(),
            principal_id: "  ".to_string(),
            decision_id: "".to_string(),
            policy_id: "".to_string(),
            zone_id: "".to_string(),
            component: "".to_string(),
        }
        .sanitized();
        assert_eq!(ctx.trace_id, "trace-missing");
        assert_eq!(ctx.principal_id, "principal-missing");
        assert_eq!(ctx.decision_id, "decision-missing");
        assert_eq!(ctx.policy_id, "policy-missing");
        assert_eq!(ctx.zone_id, "zone-missing");
        assert_eq!(ctx.component, "runtime_observability");
    }

    // ── StructuredSecurityLogEvent::required_fields_present ────────────

    #[test]
    fn log_event_required_fields_present_true() {
        let event = StructuredSecurityLogEvent {
            timestamp_ns: 1,
            trace_id: "t".to_string(),
            component: "c".to_string(),
            event_type: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
            principal_id: "p".to_string(),
            decision_id: "d".to_string(),
            policy_id: "pol".to_string(),
            zone_id: "z".to_string(),
            metadata: BTreeMap::new(),
        };
        assert!(event.required_fields_present());
    }

    #[test]
    fn log_event_required_fields_present_false_missing_trace() {
        let event = StructuredSecurityLogEvent {
            timestamp_ns: 1,
            trace_id: "".to_string(),
            component: "c".to_string(),
            event_type: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
            principal_id: "p".to_string(),
            decision_id: "d".to_string(),
            policy_id: "pol".to_string(),
            zone_id: "z".to_string(),
            metadata: BTreeMap::new(),
        };
        assert!(!event.required_fields_present());
    }

    // ── RuntimeSecurityMetrics ────────────────────────────────────────

    #[test]
    fn metrics_default_all_zeroes() {
        let m = RuntimeSecurityMetrics::default();
        assert!(m.auth_failure_total.values().all(|v| *v == 0));
        assert!(m.capability_denial_total.values().all(|v| *v == 0));
        assert!(m.replay_drop_total.values().all(|v| *v == 0));
        assert!(m.checkpoint_violation_total.values().all(|v| *v == 0));
        assert!(m.revocation_check_total.values().all(|v| *v == 0));
        assert!(m.cross_zone_reference_total.values().all(|v| *v == 0));
        assert_eq!(m.revocation_freshness_degraded_seconds, 0);
    }

    #[test]
    fn metrics_default_has_all_keys() {
        let m = RuntimeSecurityMetrics::default();
        assert_eq!(m.auth_failure_total.len(), 4);
        assert_eq!(m.capability_denial_total.len(), 6);
        assert_eq!(m.replay_drop_total.len(), 3);
        assert_eq!(m.checkpoint_violation_total.len(), 3);
        assert_eq!(m.revocation_check_total.len(), 3);
        assert_eq!(m.cross_zone_reference_total.len(), 2);
    }

    #[test]
    fn metrics_to_prometheus_contains_all_counters() {
        let prom = RuntimeSecurityMetrics::default().to_prometheus();
        assert!(prom.contains("auth_failure_total"));
        assert!(prom.contains("capability_denial_total"));
        assert!(prom.contains("replay_drop_total"));
        assert!(prom.contains("checkpoint_violation_total"));
        assert!(prom.contains("revocation_freshness_degraded_seconds"));
        assert!(prom.contains("revocation_check_total"));
        assert!(prom.contains("cross_zone_reference_total"));
    }

    #[test]
    fn metrics_to_prometheus_has_help_and_type() {
        let prom = RuntimeSecurityMetrics::default().to_prometheus();
        assert!(prom.contains("# HELP auth_failure_total"));
        assert!(prom.contains("# TYPE auth_failure_total counter"));
        assert!(prom.contains("# TYPE revocation_freshness_degraded_seconds gauge"));
    }

    // ── RuntimeSecurityObservability ──────────────────────────────────

    #[test]
    fn observability_new_empty() {
        let obs = RuntimeSecurityObservability::new();
        assert!(obs.logs().is_empty());
    }

    #[test]
    fn record_auth_failure_increments_counter() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_auth_failure(
            test_context(),
            AuthFailureType::SignatureInvalid,
            Some("secret_key"),
            None,
        );
        assert_eq!(event.event_type, "auth_failure");
        assert_eq!(event.outcome, "denied");
        assert!(event.error_code.is_some());
        assert_eq!(
            *obs.metrics()
                .auth_failure_total
                .get(&AuthFailureType::SignatureInvalid)
                .expect("operation should succeed for valid inputs"),
            1
        );
        assert_eq!(obs.logs().len(), 1);
    }

    #[test]
    fn record_auth_failure_redacts_key_material() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_auth_failure(
            test_context(),
            AuthFailureType::KeyExpired,
            Some("my_secret"),
            Some("my_token"),
        );
        let key_hash = event
            .metadata
            .get("key_material_hash")
            .expect("operation should succeed for valid inputs");
        let token_hash = event
            .metadata
            .get("token_content_hash")
            .expect("operation should succeed for valid inputs");
        assert!(key_hash.starts_with("sha256:"));
        assert!(token_hash.starts_with("sha256:"));
        assert!(!key_hash.contains("my_secret"));
        assert!(!token_hash.contains("my_token"));
    }

    #[test]
    fn record_capability_denial() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_capability_denial(
            test_context(),
            CapabilityDenialReason::InsufficientAuthority,
            "fs_read",
        );
        assert_eq!(event.event_type, "capability_denial");
        assert_eq!(event.outcome, "denied");
        assert_eq!(
            event
                .metadata
                .get("requested_capability")
                .expect("operation should succeed for valid inputs"),
            "fs_read"
        );
        assert_eq!(
            *obs.metrics()
                .capability_denial_total
                .get(&CapabilityDenialReason::InsufficientAuthority)
                .expect("operation should succeed for valid inputs"),
            1
        );
    }

    #[test]
    fn record_replay_drop() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_replay_drop(
            test_context(),
            ReplayDropReason::DuplicateSeq,
            5,
            6,
            "session-abc",
        );
        assert_eq!(event.event_type, "replay_drop");
        assert_eq!(event.outcome, "dropped");
        assert_eq!(
            event
                .metadata
                .get("received_seq")
                .expect("operation should succeed for valid inputs"),
            "5"
        );
        assert_eq!(
            event
                .metadata
                .get("expected_seq")
                .expect("operation should succeed for valid inputs"),
            "6"
        );
        // session_id is redacted
        let sid = event
            .metadata
            .get("session_id_hash")
            .expect("operation should succeed for valid inputs");
        assert!(sid.starts_with("sha256:"));
    }

    #[test]
    fn record_checkpoint_violation() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_checkpoint_violation(
            test_context(),
            CheckpointViolationType::ForkDetected,
            10,
            20,
        );
        assert_eq!(event.event_type, "checkpoint_violation");
        assert_eq!(event.outcome, "rejected");
        assert_eq!(
            *obs.metrics()
                .checkpoint_violation_total
                .get(&CheckpointViolationType::ForkDetected)
                .expect("operation should succeed for valid inputs"),
            1
        );
    }

    #[test]
    fn record_revocation_check_pass() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_revocation_check(
            test_context(),
            RevocationCheckOutcome::Pass,
            100,
            100,
            50,
            None,
        );
        assert_eq!(event.event_type, "revocation_check");
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn record_revocation_check_stale_updates_degraded_seconds() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_revocation_check(
            test_context(),
            RevocationCheckOutcome::Stale,
            80,
            100,
            50,
            Some(120),
        );
        assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 120);
    }

    #[test]
    fn record_cross_zone_reference_allowed() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_cross_zone_reference(
            test_context(),
            CrossZoneReferenceType::ProvenanceAllowed,
            "zone-a",
            "zone-b",
        );
        assert_eq!(event.event_type, "cross_zone_reference");
        assert_eq!(event.outcome, "allowed");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn record_cross_zone_reference_denied() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_cross_zone_reference(
            test_context(),
            CrossZoneReferenceType::AuthorityDenied,
            "zone-a",
            "zone-b",
        );
        assert_eq!(event.outcome, "denied");
        assert!(event.error_code.is_some());
    }

    // ── render / parse JSONL ──────────────────────────────────────────

    #[test]
    fn render_and_parse_jsonl_round_trip() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(
            test_context(),
            AuthFailureType::SignatureInvalid,
            None,
            None,
        );
        obs.record_capability_denial(test_context(), CapabilityDenialReason::Expired, "net");

        let jsonl = render_security_logs_jsonl(obs.logs());
        let parsed =
            parse_security_logs_jsonl(&jsonl).expect("operation should succeed for valid inputs");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].event_type, "auth_failure");
        assert_eq!(parsed[1].event_type, "capability_denial");
    }

    #[test]
    fn parse_jsonl_empty_input() {
        let parsed = parse_security_logs_jsonl("").expect("operation should succeed for valid inputs");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_jsonl_blank_lines_skipped() {
        let parsed =
            parse_security_logs_jsonl("\n  \n").expect("operation should succeed for valid inputs");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_jsonl_invalid_json_errors() {
        let result = parse_security_logs_jsonl("not valid json");
        assert!(result.is_err());
    }

    // ── redact_sensitive_value ─────────────────────────────────────────

    #[test]
    fn redact_deterministic() {
        let a = redact_sensitive_value("secret");
        let b = redact_sensitive_value("secret");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
        assert!(!a.contains("secret"));
    }

    #[test]
    fn redact_different_inputs_differ() {
        assert_ne!(
            redact_sensitive_value("secret1"),
            redact_sensitive_value("secret2")
        );
    }

    // ── sanitize_required ─────────────────────────────────────────────

    #[test]
    fn sanitize_required_non_empty() {
        assert_eq!(sanitize_required("hello", "fallback"), "hello");
    }

    #[test]
    fn sanitize_required_empty_uses_fallback() {
        assert_eq!(sanitize_required("", "fallback"), "fallback");
        assert_eq!(sanitize_required("  ", "fallback"), "fallback");
    }

    // ── export methods ────────────────────────────────────────────────

    #[test]
    fn export_prometheus_metrics_not_empty() {
        let obs = RuntimeSecurityObservability::new();
        let prom = obs.export_prometheus_metrics();
        assert!(!prom.is_empty());
        assert!(prom.contains("auth_failure_total"));
    }

    #[test]
    fn export_logs_jsonl_empty_when_no_events() {
        let obs = RuntimeSecurityObservability::new();
        assert!(obs.export_logs_jsonl().is_empty());
    }

    // ── multiple events accumulate ────────────────────────────────────

    #[test]
    fn multiple_auth_failures_accumulate() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(
            test_context(),
            AuthFailureType::SignatureInvalid,
            None,
            None,
        );
        obs.record_auth_failure(
            test_context(),
            AuthFailureType::SignatureInvalid,
            None,
            None,
        );
        obs.record_auth_failure(test_context(), AuthFailureType::KeyRevoked, None, None);
        assert_eq!(
            *obs.metrics()
                .auth_failure_total
                .get(&AuthFailureType::SignatureInvalid)
                .expect("operation should succeed for valid inputs"),
            2
        );
        assert_eq!(
            *obs.metrics()
                .auth_failure_total
                .get(&AuthFailureType::KeyRevoked)
                .expect("operation should succeed for valid inputs"),
            1
        );
        assert_eq!(obs.logs().len(), 3);
    }

    // ── serde round-trips ──────────────────────────────────────────────

    #[test]
    fn metrics_serde_round_trip() {
        let m = RuntimeSecurityMetrics::default();
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let back: RuntimeSecurityMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, m);
    }

    #[test]
    fn observability_serde_round_trip() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(test_context(), AuthFailureType::KeyExpired, None, None);
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        let back: RuntimeSecurityObservability =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, obs);
    }

    #[test]
    fn security_event_type_serde_round_trip() {
        for t in [
            SecurityEventType::AuthFailure,
            SecurityEventType::CapabilityDenial,
            SecurityEventType::ReplayDrop,
            SecurityEventType::CheckpointViolation,
            SecurityEventType::RevocationCheck,
            SecurityEventType::CrossZoneReference,
        ] {
            let json = serde_json::to_string(&t).expect("serialize derived Serialize");
            let back: SecurityEventType =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, t);
        }
    }

    #[test]
    fn security_outcome_serde_round_trip() {
        for o in [
            SecurityOutcome::Pass,
            SecurityOutcome::Allowed,
            SecurityOutcome::Denied,
            SecurityOutcome::Dropped,
            SecurityOutcome::Rejected,
            SecurityOutcome::Degraded,
        ] {
            let json = serde_json::to_string(&o).expect("serialize derived Serialize");
            let back: SecurityOutcome =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, o);
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn auth_failure_type_as_label_distinct() {
        let set: std::collections::BTreeSet<&str> =
            AuthFailureType::ALL.iter().map(|a| a.as_label()).collect();
        assert_eq!(set.len(), AuthFailureType::ALL.len());
    }

    #[test]
    fn capability_denial_reason_as_label_distinct() {
        let set: std::collections::BTreeSet<&str> = CapabilityDenialReason::ALL
            .iter()
            .map(|c| c.as_label())
            .collect();
        assert_eq!(set.len(), CapabilityDenialReason::ALL.len());
    }

    #[test]
    fn replay_drop_reason_as_label_distinct() {
        let set: std::collections::BTreeSet<&str> =
            ReplayDropReason::ALL.iter().map(|r| r.as_label()).collect();
        assert_eq!(set.len(), ReplayDropReason::ALL.len());
    }

    #[test]
    fn checkpoint_violation_as_label_distinct() {
        let set: std::collections::BTreeSet<&str> = CheckpointViolationType::ALL
            .iter()
            .map(|c| c.as_label())
            .collect();
        assert_eq!(set.len(), CheckpointViolationType::ALL.len());
    }

    #[test]
    fn revocation_check_outcome_as_label_distinct() {
        let set: std::collections::BTreeSet<&str> = RevocationCheckOutcome::ALL
            .iter()
            .map(|r| r.as_label())
            .collect();
        assert_eq!(set.len(), RevocationCheckOutcome::ALL.len());
    }

    #[test]
    fn cross_zone_reference_type_as_label_distinct() {
        let set: std::collections::BTreeSet<&str> = CrossZoneReferenceType::ALL
            .iter()
            .map(|c| c.as_label())
            .collect();
        assert_eq!(set.len(), CrossZoneReferenceType::ALL.len());
    }

    #[test]
    fn security_event_type_as_str_distinct() {
        let all = [
            SecurityEventType::AuthFailure,
            SecurityEventType::CapabilityDenial,
            SecurityEventType::ReplayDrop,
            SecurityEventType::CheckpointViolation,
            SecurityEventType::RevocationCheck,
            SecurityEventType::CrossZoneReference,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn security_outcome_as_str_distinct() {
        let all = [
            SecurityOutcome::Pass,
            SecurityOutcome::Allowed,
            SecurityOutcome::Denied,
            SecurityOutcome::Dropped,
            SecurityOutcome::Rejected,
            SecurityOutcome::Degraded,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|o| o.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_auth_failure_type_copy_semantics() {
        let a = AuthFailureType::KeyRevoked;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, AuthFailureType::KeyRevoked);
    }

    #[test]
    fn enrichment_auth_failure_type_ord_ordering() {
        // Enum variants derive Ord in declaration order
        assert!(AuthFailureType::SignatureInvalid < AuthFailureType::KeyExpired);
        assert!(AuthFailureType::KeyExpired < AuthFailureType::KeyRevoked);
        assert!(AuthFailureType::KeyRevoked < AuthFailureType::AttestationInvalid);
    }

    #[test]
    fn enrichment_capability_denial_reason_ord_ordering() {
        assert!(
            CapabilityDenialReason::InsufficientAuthority < CapabilityDenialReason::CeilingExceeded
        );
        assert!(CapabilityDenialReason::Expired < CapabilityDenialReason::NotYetValid);
    }

    #[test]
    fn enrichment_auth_failure_type_hash_in_btreeset() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for t in AuthFailureType::ALL {
            assert!(set.insert(t));
        }
        // Inserting duplicates should fail
        for t in AuthFailureType::ALL {
            assert!(!set.insert(t));
        }
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn enrichment_security_event_context_clone() {
        let ctx = test_context();
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
        assert_eq!(cloned.timestamp_ns, 1_000_000);
        assert_eq!(cloned.trace_id, "trace-001");
    }

    #[test]
    fn enrichment_security_event_context_serde_roundtrip() {
        let ctx = test_context();
        let json = serde_json::to_string(&ctx).expect("serialize derived Serialize");
        let back: SecurityEventContext =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, ctx);
    }

    #[test]
    fn enrichment_security_event_context_json_field_names() {
        let ctx = test_context();
        let val: serde_json::Value =
            serde_json::to_value(&ctx).expect("serialization should succeed");
        let obj = val
            .as_object()
            .expect("operation should succeed for valid inputs");
        assert!(obj.contains_key("timestamp_ns"));
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("principal_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("zone_id"));
        assert!(obj.contains_key("component"));
        assert_eq!(obj.len(), 7);
    }

    #[test]
    fn enrichment_structured_log_event_serde_with_metadata() {
        let mut metadata = BTreeMap::new();
        metadata.insert("key1".to_string(), "val1".to_string());
        metadata.insert("key2".to_string(), "val2".to_string());
        let event = StructuredSecurityLogEvent {
            timestamp_ns: 42,
            trace_id: "t".to_string(),
            component: "c".to_string(),
            event_type: "auth_failure".to_string(),
            outcome: "denied".to_string(),
            error_code: Some("E1001".to_string()),
            principal_id: "p".to_string(),
            decision_id: "d".to_string(),
            policy_id: "pol".to_string(),
            zone_id: "z".to_string(),
            metadata,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let back: StructuredSecurityLogEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, event);
        assert_eq!(back.metadata.len(), 2);
        assert_eq!(
            back.metadata
                .get("key1")
                .expect("operation should succeed for valid inputs"),
            "val1"
        );
    }

    #[test]
    fn enrichment_required_fields_false_missing_component() {
        let event = StructuredSecurityLogEvent {
            timestamp_ns: 1,
            trace_id: "t".to_string(),
            component: "".to_string(),
            event_type: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
            principal_id: "p".to_string(),
            decision_id: "d".to_string(),
            policy_id: "pol".to_string(),
            zone_id: "z".to_string(),
            metadata: BTreeMap::new(),
        };
        assert!(!event.required_fields_present());
    }

    #[test]
    fn enrichment_required_fields_false_missing_zone_id() {
        let event = StructuredSecurityLogEvent {
            timestamp_ns: 1,
            trace_id: "t".to_string(),
            component: "c".to_string(),
            event_type: "e".to_string(),
            outcome: "o".to_string(),
            error_code: None,
            principal_id: "p".to_string(),
            decision_id: "d".to_string(),
            policy_id: "pol".to_string(),
            zone_id: "".to_string(),
            metadata: BTreeMap::new(),
        };
        assert!(!event.required_fields_present());
    }

    #[test]
    fn enrichment_prometheus_with_nonzero_values() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(test_context(), AuthFailureType::KeyExpired, None, None);
        obs.record_auth_failure(test_context(), AuthFailureType::KeyExpired, None, None);
        obs.record_replay_drop(test_context(), ReplayDropReason::StaleSeq, 1, 5, "sess");
        let prom = obs.export_prometheus_metrics();
        assert!(prom.contains("auth_failure_total{type=\"key_expired\"} 2"));
        assert!(prom.contains("replay_drop_total{reason=\"stale_seq\"} 1"));
        // Other counters remain zero
        assert!(prom.contains("auth_failure_total{type=\"signature_invalid\"} 0"));
    }

    #[test]
    fn enrichment_multiple_event_types_accumulate_independently() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(
            test_context(),
            AuthFailureType::AttestationInvalid,
            None,
            None,
        );
        obs.record_capability_denial(
            test_context(),
            CapabilityDenialReason::CeilingExceeded,
            "network",
        );
        obs.record_checkpoint_violation(
            test_context(),
            CheckpointViolationType::QuorumInsufficient,
            1,
            2,
        );
        assert_eq!(obs.logs().len(), 3);
        assert_eq!(
            *obs.metrics()
                .auth_failure_total
                .get(&AuthFailureType::AttestationInvalid)
                .expect("operation should succeed for valid inputs"),
            1
        );
        assert_eq!(
            *obs.metrics()
                .capability_denial_total
                .get(&CapabilityDenialReason::CeilingExceeded)
                .expect("operation should succeed for valid inputs"),
            1
        );
        assert_eq!(
            *obs.metrics()
                .checkpoint_violation_total
                .get(&CheckpointViolationType::QuorumInsufficient)
                .expect("operation should succeed for valid inputs"),
            1
        );
    }

    #[test]
    fn enrichment_capability_denial_empty_capability_sanitized() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_capability_denial(
            test_context(),
            CapabilityDenialReason::AttenuationViolation,
            "",
        );
        assert_eq!(
            event
                .metadata
                .get("requested_capability")
                .expect("operation should succeed for valid inputs"),
            "unspecified"
        );
    }

    #[test]
    fn enrichment_cross_zone_empty_zones_sanitized() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_cross_zone_reference(
            test_context(),
            CrossZoneReferenceType::ProvenanceAllowed,
            "",
            "  ",
        );
        assert_eq!(
            event
                .metadata
                .get("source_zone")
                .expect("operation should succeed for valid inputs"),
            "source-zone-missing"
        );
        assert_eq!(
            event
                .metadata
                .get("target_zone")
                .expect("operation should succeed for valid inputs"),
            "target-zone-missing"
        );
    }

    #[test]
    fn enrichment_revocation_check_revoked_outcome() {
        let mut obs = RuntimeSecurityObservability::new();
        let event = obs.record_revocation_check(
            test_context(),
            RevocationCheckOutcome::Revoked,
            50,
            100,
            25,
            None,
        );
        assert_eq!(event.outcome, "denied");
        assert!(event.error_code.is_some());
        assert_eq!(
            event
                .metadata
                .get("staleness_gap")
                .expect("operation should succeed for valid inputs"),
            "50"
        );
        assert_eq!(
            *obs.metrics()
                .revocation_check_total
                .get(&RevocationCheckOutcome::Revoked)
                .expect("operation should succeed for valid inputs"),
            1
        );
    }

    #[test]
    fn enrichment_revocation_check_staleness_gap_saturating() {
        let mut obs = RuntimeSecurityObservability::new();
        // local_head > expected_head: saturating_sub yields 0
        let event = obs.record_revocation_check(
            test_context(),
            RevocationCheckOutcome::Pass,
            200,
            100,
            50,
            None,
        );
        assert_eq!(
            event
                .metadata
                .get("staleness_gap")
                .expect("operation should succeed for valid inputs"),
            "0"
        );
    }

    #[test]
    fn enrichment_replay_drop_all_reasons() {
        let mut obs = RuntimeSecurityObservability::new();
        for reason in ReplayDropReason::ALL {
            obs.record_replay_drop(test_context(), reason, 1, 2, "s");
        }
        for reason in ReplayDropReason::ALL {
            assert_eq!(
                *obs.metrics()
                    .replay_drop_total
                    .get(&reason)
                    .expect("operation should succeed for valid inputs"),
                1
            );
        }
        assert_eq!(obs.logs().len(), 3);
    }

    #[test]
    fn enrichment_checkpoint_violation_all_types() {
        let mut obs = RuntimeSecurityObservability::new();
        for viol in CheckpointViolationType::ALL {
            obs.record_checkpoint_violation(test_context(), viol, 10, 20);
        }
        for viol in CheckpointViolationType::ALL {
            assert_eq!(
                *obs.metrics()
                    .checkpoint_violation_total
                    .get(&viol)
                    .expect("operation should succeed for valid inputs"),
                1
            );
        }
        assert_eq!(obs.logs().len(), 3);
    }

    #[test]
    fn enrichment_metrics_serde_with_nonzero_values() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(
            test_context(),
            AuthFailureType::SignatureInvalid,
            None,
            None,
        );
        obs.record_revocation_check(
            test_context(),
            RevocationCheckOutcome::Stale,
            10,
            100,
            50,
            Some(42),
        );
        let json = serde_json::to_string(&obs.metrics).expect("serialize derived Serialize");
        let back: RuntimeSecurityMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(
            *back
                .auth_failure_total
                .get(&AuthFailureType::SignatureInvalid)
                .expect("operation should succeed for valid inputs"),
            1
        );
        assert_eq!(back.revocation_freshness_degraded_seconds, 42);
    }

    #[test]
    fn enrichment_constants_match_expected_values() {
        assert_eq!(AUTH_FAILURE_TOTAL, "auth_failure_total");
        assert_eq!(CAPABILITY_DENIAL_TOTAL, "capability_denial_total");
        assert_eq!(REPLAY_DROP_TOTAL, "replay_drop_total");
        assert_eq!(CHECKPOINT_VIOLATION_TOTAL, "checkpoint_violation_total");
        assert_eq!(
            REVOCATION_FRESHNESS_DEGRADED_SECONDS,
            "revocation_freshness_degraded_seconds"
        );
        assert_eq!(REVOCATION_CHECK_TOTAL, "revocation_check_total");
        assert_eq!(CROSS_ZONE_REFERENCE_TOTAL, "cross_zone_reference_total");
    }

    #[test]
    fn enrichment_jsonl_export_multiline() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(
            test_context(),
            AuthFailureType::SignatureInvalid,
            None,
            None,
        );
        obs.record_replay_drop(
            test_context(),
            ReplayDropReason::CrossSession,
            3,
            4,
            "sess-x",
        );
        obs.record_cross_zone_reference(
            test_context(),
            CrossZoneReferenceType::AuthorityDenied,
            "z1",
            "z2",
        );
        let jsonl = obs.export_logs_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 3);
        // Each line is valid JSON
        for line in &lines {
            let val: serde_json::Value =
                serde_json::from_str(line).expect("deserialize known-valid JSON");
            assert!(val.is_object());
        }
        // Roundtrip through parse
        let parsed =
            parse_security_logs_jsonl(&jsonl).expect("operation should succeed for valid inputs");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].event_type, "auth_failure");
        assert_eq!(parsed[1].event_type, "replay_drop");
        assert_eq!(parsed[2].event_type, "cross_zone_reference");
    }

    #[test]
    fn enrichment_redact_empty_string() {
        let hash = redact_sensitive_value("");
        assert!(hash.starts_with("sha256:"));
        // SHA-256 of empty string is well-known
        assert_eq!(hash.len(), "sha256:".len() + 64);
    }

    #[test]
    fn enrichment_observability_clone_independence() {
        let mut obs = RuntimeSecurityObservability::new();
        obs.record_auth_failure(
            test_context(),
            AuthFailureType::SignatureInvalid,
            None,
            None,
        );
        let cloned = obs.clone();
        // Mutate original; clone unaffected
        obs.record_auth_failure(test_context(), AuthFailureType::KeyExpired, None, None);
        assert_eq!(obs.logs().len(), 2);
        assert_eq!(cloned.logs().len(), 1);
    }
}
