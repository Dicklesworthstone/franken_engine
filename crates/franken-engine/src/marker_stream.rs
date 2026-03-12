//! Append-only hash-linked decision marker stream for high-impact
//! security/policy transitions.
//!
//! Every critical decision (quarantine, revocation, epoch transition,
//! policy activation, emergency override) appends a tamper-evident marker
//! to a hash-linked stream that provides an immutable audit trail.
//!
//! Uses Tier 2 ContentHash for marker linking and Tier 3 AuthenticityHash
//! for signed integrity checkpoints.
//!
//! Plan references: Section 10.11 item 28, 9G.9 (three-tier integrity +
//! append-only decision stream), Top-10 #3, #10.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};

// ---------------------------------------------------------------------------
// DecisionType — types of decisions that produce markers
// ---------------------------------------------------------------------------

/// Types of high-impact decisions tracked in the marker stream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionType {
    /// Quarantine, suspend, or terminate decisions.
    SecurityAction { action: SecurityActionKind },
    /// Policy activation, deactivation, epoch advancement.
    PolicyTransition { transition: PolicyTransitionKind },
    /// Revocation issuance or propagation confirmation.
    RevocationEvent { revocation: RevocationKind },
    /// Security epoch change with before/after state.
    EpochTransition { from_epoch: u64, to_epoch: u64 },
    /// Operator override of automated decision.
    EmergencyOverride { override_reason: String },
    /// E-process guardrail activation.
    GuardrailTriggered { guardrail_id: String },
}

/// Sub-types of security actions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityActionKind {
    Quarantine,
    Suspend,
    Terminate,
}

impl fmt::Display for SecurityActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quarantine => write!(f, "quarantine"),
            Self::Suspend => write!(f, "suspend"),
            Self::Terminate => write!(f, "terminate"),
        }
    }
}

/// Sub-types of policy transitions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyTransitionKind {
    Activation,
    Deactivation,
    EpochAdvancement,
}

impl fmt::Display for PolicyTransitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Activation => write!(f, "activation"),
            Self::Deactivation => write!(f, "deactivation"),
            Self::EpochAdvancement => write!(f, "epoch_advancement"),
        }
    }
}

/// Sub-types of revocation events.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RevocationKind {
    Issuance,
    PropagationConfirmation,
}

impl fmt::Display for RevocationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Issuance => write!(f, "issuance"),
            Self::PropagationConfirmation => write!(f, "propagation_confirmation"),
        }
    }
}

impl fmt::Display for DecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityAction { action } => write!(f, "security_action:{action}"),
            Self::PolicyTransition { transition } => write!(f, "policy_transition:{transition}"),
            Self::RevocationEvent { revocation } => write!(f, "revocation_event:{revocation}"),
            Self::EpochTransition {
                from_epoch,
                to_epoch,
            } => write!(f, "epoch_transition:{from_epoch}->{to_epoch}"),
            Self::EmergencyOverride { .. } => write!(f, "emergency_override"),
            Self::GuardrailTriggered { guardrail_id } => {
                write!(f, "guardrail_triggered:{guardrail_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CorrelationId / TraceContext / RedactedPayload
// ---------------------------------------------------------------------------

/// Correlation identifier linking related audit markers across components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CorrelationId(String);

impl CorrelationId {
    pub fn new(raw: impl Into<String>) -> Result<Self, &'static str> {
        let value = raw.into();
        if value.is_empty() {
            return Err("correlation_id must not be empty");
        }
        if value.len() > 128 {
            return Err("correlation_id must be <= 128 bytes");
        }
        if !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
        {
            return Err("correlation_id has unsupported characters");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Optional full trace context (W3C trace context compatible fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    pub traceparent: String,
    pub tracestate: Option<String>,
    pub baggage: Option<String>,
}

/// Redacted payload material stored in the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedPayload {
    /// Redacted summary safe for append-only chain storage.
    pub redacted_summary: String,
    /// Hash of full (potentially sensitive) payload.
    pub payload_hash: ContentHash,
    /// Whether redaction was applied before persistence.
    pub redaction_applied: bool,
}

// ---------------------------------------------------------------------------
// DecisionMarker — a single marker in the stream
// ---------------------------------------------------------------------------

/// A single marker in the hash-linked decision stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionMarker {
    /// Unique marker identifier (monotonically increasing).
    pub marker_id: u64,
    /// Hash of the previous marker (genesis marker has all zeros).
    pub prev_marker_hash: ContentHash,
    /// Hash of this marker (computed over all fields except this one).
    pub marker_hash: ContentHash,
    /// Virtual timestamp (tick count for determinism).
    pub timestamp_ticks: u64,
    /// Security epoch at time of decision.
    pub epoch_id: u64,
    /// Type of decision that produced this marker.
    pub decision_type: DecisionType,
    /// Decision identifier for correlation with evidence entries.
    pub decision_id: String,
    /// Optional policy identifier active at decision time.
    pub policy_id: Option<String>,
    /// Correlation ID that links this marker to a larger flow.
    pub correlation_id: CorrelationId,
    /// Optional full trace context for deep distributed tracing.
    pub trace_context: Option<TraceContext>,
    /// Optional principal identifier.
    pub principal_id: Option<String>,
    /// Optional trust/zone identifier.
    pub zone_id: Option<String>,
    /// Optional stable error code.
    pub error_code: Option<String>,
    /// Hash linking to the full evidence entry in the evidence ledger.
    pub evidence_entry_hash: ContentHash,
    /// Actor (agent, operator, or system component) that made the decision.
    pub actor: String,
    /// Redacted payload persisted in the append-only chain.
    pub redacted_payload: RedactedPayload,
}

// ---------------------------------------------------------------------------
// MarkerInput — input bundle for appending a marker (avoids too_many_arguments)
// ---------------------------------------------------------------------------

/// Input fields required to append a new decision marker.
#[derive(Debug, Clone)]
pub struct MarkerInput {
    /// Virtual timestamp (tick count for determinism).
    pub timestamp_ticks: u64,
    /// Security epoch at time of decision.
    pub epoch_id: u64,
    /// Type of decision that produced this marker.
    pub decision_type: DecisionType,
    /// Decision identifier for correlation with evidence entries.
    pub decision_id: String,
    /// Optional policy identifier active at decision time.
    pub policy_id: Option<String>,
    /// Correlation ID that links this marker to a larger flow.
    pub correlation_id: CorrelationId,
    /// Optional full trace context.
    pub trace_context: Option<TraceContext>,
    /// Optional principal identifier.
    pub principal_id: Option<String>,
    /// Optional trust/zone identifier.
    pub zone_id: Option<String>,
    /// Optional stable error code.
    pub error_code: Option<String>,
    /// Hash linking to the full evidence entry in the evidence ledger.
    pub evidence_entry_hash: ContentHash,
    /// Actor (agent, operator, or system component) that made the decision.
    pub actor: String,
    /// Concise payload summary (already redacted).
    pub payload_summary: String,
    /// Optional full payload used only for hashing before redaction.
    pub full_payload: Option<String>,
    /// Trace identifier for structured audit events.
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// ChainIntegrityError — hash chain verification failures
// ---------------------------------------------------------------------------

/// Error when hash chain integrity verification fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainIntegrityError {
    /// A marker's computed hash does not match its stored hash.
    MarkerHashMismatch {
        marker_id: u64,
        expected: ContentHash,
        computed: ContentHash,
    },
    /// A marker's prev_marker_hash does not match the preceding marker's hash.
    ChainLinkBroken {
        marker_id: u64,
        expected_prev: ContentHash,
        actual_prev: ContentHash,
    },
    /// The stream is empty (cannot verify an empty chain).
    EmptyStream,
    /// Marker IDs are not monotonically increasing.
    NonMonotonicId { marker_id: u64, prev_marker_id: u64 },
    /// Signed chain head does not match recomputed head.
    HeadMismatch,
}

impl fmt::Display for ChainIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MarkerHashMismatch { marker_id, .. } => {
                write!(f, "marker {marker_id}: hash mismatch")
            }
            Self::ChainLinkBroken { marker_id, .. } => {
                write!(f, "marker {marker_id}: chain link broken")
            }
            Self::EmptyStream => write!(f, "empty stream"),
            Self::NonMonotonicId {
                marker_id,
                prev_marker_id,
            } => write!(f, "non-monotonic: {marker_id} after {prev_marker_id}"),
            Self::HeadMismatch => write!(f, "chain head mismatch"),
        }
    }
}

impl std::error::Error for ChainIntegrityError {}

// ---------------------------------------------------------------------------
// IntegrityCheckpoint — periodic signed checkpoint
// ---------------------------------------------------------------------------

/// A signed integrity checkpoint emitted every N markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityCheckpoint {
    /// Marker ID at which this checkpoint was created.
    pub at_marker_id: u64,
    /// Hash of the marker at the checkpoint position.
    pub marker_hash: ContentHash,
    /// Number of markers in the stream at checkpoint time.
    pub chain_length: u64,
    /// Signed hash (Tier 3) covering the checkpoint fields.
    pub signed_hash: AuthenticityHash,
}

/// Signed head for the append-only chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainHead {
    /// Latest marker ID.
    pub head_marker_id: u64,
    /// Latest marker hash.
    pub latest_marker_hash: ContentHash,
    /// Rolling hash over the chain.
    pub rolling_chain_hash: ContentHash,
    /// Signed hash covering head fields.
    pub signed_head_hash: AuthenticityHash,
}

// ---------------------------------------------------------------------------
// MarkerEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for marker stream operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkerEvent {
    pub marker_id: u64,
    pub marker_type: String,
    pub chain_length: u64,
    pub decision_id: String,
    pub policy_id: Option<String>,
    pub principal_id: Option<String>,
    pub correlation_id: String,
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// DecisionMarkerStream — the append-only stream
// ---------------------------------------------------------------------------

/// Append-only hash-linked decision marker stream.
///
/// Markers can only be appended, never modified or deleted. The hash chain
/// ensures tamper detection.
#[derive(Debug)]
pub struct DecisionMarkerStream {
    markers: Vec<DecisionMarker>,
    next_marker_id: u64,
    checkpoints: Vec<IntegrityCheckpoint>,
    chain_head: Option<AuditChainHead>,
    rolling_chain_hash: ContentHash,
    checkpoint_interval: u64,
    checkpoint_key: Vec<u8>,
    events: Vec<MarkerEvent>,
}

impl DecisionMarkerStream {
    /// Create a new empty marker stream.
    ///
    /// `checkpoint_interval`: emit a signed checkpoint every N markers.
    /// `checkpoint_key`: key material for Tier 3 signed checkpoints.
    pub fn new(checkpoint_interval: u64, checkpoint_key: Vec<u8>) -> Self {
        Self {
            markers: Vec::new(),
            next_marker_id: 1,
            checkpoints: Vec::new(),
            chain_head: None,
            rolling_chain_hash: ContentHash([0u8; 32]),
            checkpoint_interval,
            checkpoint_key,
            events: Vec::new(),
        }
    }

    /// Number of markers in the stream.
    pub fn len(&self) -> usize {
        self.markers.len()
    }

    /// Whether the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
    }

    /// Append a new decision marker to the stream.
    pub fn append(&mut self, input: MarkerInput) -> &DecisionMarker {
        let marker_id = self.next_marker_id;
        self.next_marker_id += 1;

        // Previous marker hash (genesis = all zeros).
        let prev_marker_hash = self
            .markers
            .last()
            .map(|m| m.marker_hash)
            .unwrap_or(ContentHash([0u8; 32]));

        let decision_type_str = input.decision_type.to_string();
        let decision_id_for_event = input.decision_id.clone();
        let policy_id_for_event = input.policy_id.clone();
        let principal_id_for_event = input.principal_id.clone();
        let payload_material = input
            .full_payload
            .clone()
            .unwrap_or_else(|| input.payload_summary.clone());
        let payload_hash = ContentHash::compute(payload_material.as_bytes());
        let redacted_payload = RedactedPayload {
            redacted_summary: input.payload_summary,
            payload_hash,
            redaction_applied: input.full_payload.is_some(),
        };

        // Build marker with placeholder hash, then compute real hash.
        let mut marker = DecisionMarker {
            marker_id,
            prev_marker_hash,
            marker_hash: ContentHash([0u8; 32]), // placeholder
            timestamp_ticks: input.timestamp_ticks,
            epoch_id: input.epoch_id,
            decision_type: input.decision_type,
            decision_id: input.decision_id,
            policy_id: input.policy_id,
            correlation_id: input.correlation_id.clone(),
            trace_context: input.trace_context,
            principal_id: input.principal_id,
            zone_id: input.zone_id,
            error_code: input.error_code.clone(),
            evidence_entry_hash: input.evidence_entry_hash,
            actor: input.actor,
            redacted_payload,
        };

        marker.marker_hash = compute_marker_hash(&marker);

        self.markers.push(marker);
        self.update_chain_head();

        // Emit audit event.
        self.events.push(MarkerEvent {
            marker_id,
            marker_type: decision_type_str,
            chain_length: self.markers.len() as u64,
            decision_id: decision_id_for_event,
            policy_id: policy_id_for_event,
            principal_id: principal_id_for_event,
            correlation_id: input.correlation_id.to_string(),
            trace_id: input.trace_id,
            component: "marker_stream".to_string(),
            event: "marker_appended".to_string(),
            outcome: "ok".to_string(),
            error_code: input.error_code,
        });

        // Check if we should emit a checkpoint.
        if self.checkpoint_interval > 0 && marker_id.is_multiple_of(self.checkpoint_interval) {
            self.emit_checkpoint(marker_id);
        }

        self.markers.last().expect("just pushed")
    }

    /// Get a marker by its ID.
    pub fn get(&self, marker_id: u64) -> Option<&DecisionMarker> {
        self.markers.iter().find(|m| m.marker_id == marker_id)
    }

    /// Verify the hash chain integrity of the entire stream.
    pub fn verify_chain(&self) -> Result<(), ChainIntegrityError> {
        if self.markers.is_empty() {
            return Err(ChainIntegrityError::EmptyStream);
        }

        let genesis_prev = ContentHash([0u8; 32]);

        for (i, marker) in self.markers.iter().enumerate() {
            // Verify monotonic IDs.
            if i > 0 {
                let prev = &self.markers[i - 1];
                if marker.marker_id <= prev.marker_id {
                    return Err(ChainIntegrityError::NonMonotonicId {
                        marker_id: marker.marker_id,
                        prev_marker_id: prev.marker_id,
                    });
                }
            }

            // Verify prev_marker_hash link.
            let expected_prev = if i == 0 {
                &genesis_prev
            } else {
                &self.markers[i - 1].marker_hash
            };

            if marker.prev_marker_hash != *expected_prev {
                return Err(ChainIntegrityError::ChainLinkBroken {
                    marker_id: marker.marker_id,
                    expected_prev: *expected_prev,
                    actual_prev: marker.prev_marker_hash,
                });
            }

            // Verify marker hash.
            let computed = compute_marker_hash(marker);

            if marker.marker_hash != computed {
                return Err(ChainIntegrityError::MarkerHashMismatch {
                    marker_id: marker.marker_id,
                    expected: marker.marker_hash,
                    computed,
                });
            }
        }

        Ok(())
    }

    /// Verify chain integrity between two marker IDs (inclusive).
    pub fn verify_range(&self, from_id: u64, to_id: u64) -> Result<(), ChainIntegrityError> {
        let from_idx = self.markers.iter().position(|m| m.marker_id == from_id);
        let to_idx = self.markers.iter().position(|m| m.marker_id == to_id);

        let (from_idx, to_idx) = match (from_idx, to_idx) {
            (Some(f), Some(t)) => (f, t),
            _ => return Err(ChainIntegrityError::EmptyStream),
        };

        for i in from_idx..=to_idx {
            let marker = &self.markers[i];

            if i > from_idx {
                let prev = &self.markers[i - 1];
                if marker.prev_marker_hash != prev.marker_hash {
                    return Err(ChainIntegrityError::ChainLinkBroken {
                        marker_id: marker.marker_id,
                        expected_prev: prev.marker_hash,
                        actual_prev: marker.prev_marker_hash,
                    });
                }
            }

            let computed = compute_marker_hash(marker);

            if marker.marker_hash != computed {
                return Err(ChainIntegrityError::MarkerHashMismatch {
                    marker_id: marker.marker_id,
                    expected: marker.marker_hash,
                    computed,
                });
            }
        }

        Ok(())
    }

    /// All markers in the stream.
    pub fn markers(&self) -> &[DecisionMarker] {
        &self.markers
    }

    /// All checkpoints.
    pub fn checkpoints(&self) -> &[IntegrityCheckpoint] {
        &self.checkpoints
    }

    /// Latest signed chain head.
    pub fn chain_head(&self) -> Option<&AuditChainHead> {
        self.chain_head.as_ref()
    }

    /// Query markers by correlation ID.
    pub fn by_correlation_id(&self, correlation_id: &str) -> Vec<&DecisionMarker> {
        self.markers
            .iter()
            .filter(|marker| marker.correlation_id.as_str() == correlation_id)
            .collect()
    }

    /// Query markers by decision type display value.
    pub fn by_event_type(&self, event_type: &str) -> Vec<&DecisionMarker> {
        self.markers
            .iter()
            .filter(|marker| marker.decision_type.to_string() == event_type)
            .collect()
    }

    /// Query markers by principal identifier.
    pub fn by_principal_id(&self, principal_id: &str) -> Vec<&DecisionMarker> {
        self.markers
            .iter()
            .filter(|marker| marker.principal_id.as_deref() == Some(principal_id))
            .collect()
    }

    /// Query markers by inclusive timestamp range.
    pub fn by_time_range(&self, start_ticks: u64, end_ticks: u64) -> Vec<&DecisionMarker> {
        self.markers
            .iter()
            .filter(|marker| {
                marker.timestamp_ticks >= start_ticks && marker.timestamp_ticks <= end_ticks
            })
            .collect()
    }

    /// Query markers by stable error code.
    pub fn by_error_code(&self, error_code: &str) -> Vec<&DecisionMarker> {
        self.markers
            .iter()
            .filter(|marker| marker.error_code.as_deref() == Some(error_code))
            .collect()
    }

    /// Verify the currently stored chain head against recomputed state.
    pub fn verify_head(&self) -> Result<(), ChainIntegrityError> {
        if self.markers.is_empty() {
            return Ok(());
        }

        let Some(existing_head) = self.chain_head.as_ref() else {
            return Err(ChainIntegrityError::HeadMismatch);
        };

        let latest = self.markers.last().expect("checked non-empty");
        let expected_rolling = recompute_rolling_hash(&self.markers);
        let expected_signed = sign_chain_head(
            &self.checkpoint_key,
            latest.marker_id,
            &latest.marker_hash,
            &expected_rolling,
        );

        if existing_head.head_marker_id != latest.marker_id
            || existing_head.latest_marker_hash != latest.marker_hash
            || existing_head.rolling_chain_hash != expected_rolling
            || existing_head.signed_head_hash != expected_signed
        {
            return Err(ChainIntegrityError::HeadMismatch);
        }

        Ok(())
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<MarkerEvent> {
        std::mem::take(&mut self.events)
    }

    /// Emit a signed integrity checkpoint.
    fn emit_checkpoint(&mut self, marker_id: u64) {
        if let Some(marker) = self.get(marker_id) {
            let marker_hash = marker.marker_hash;
            let chain_length = self.markers.len() as u64;

            // Build checkpoint preimage for signing.
            let mut preimage = Vec::new();
            preimage.extend_from_slice(&marker_id.to_be_bytes());
            preimage.extend_from_slice(marker_hash.as_bytes());
            preimage.extend_from_slice(&chain_length.to_be_bytes());

            let signed_hash = AuthenticityHash::compute_keyed(&self.checkpoint_key, &preimage);

            self.checkpoints.push(IntegrityCheckpoint {
                at_marker_id: marker_id,
                marker_hash,
                chain_length,
                signed_hash,
            });
        }
    }

    fn update_chain_head(&mut self) {
        let Some(latest) = self.markers.last() else {
            self.chain_head = None;
            self.rolling_chain_hash = ContentHash([0u8; 32]);
            return;
        };

        self.rolling_chain_hash = compute_rolling_hash(
            &self.rolling_chain_hash,
            latest.marker_id,
            &latest.marker_hash,
        );
        let signed_head = sign_chain_head(
            &self.checkpoint_key,
            latest.marker_id,
            &latest.marker_hash,
            &self.rolling_chain_hash,
        );
        self.chain_head = Some(AuditChainHead {
            head_marker_id: latest.marker_id,
            latest_marker_hash: latest.marker_hash,
            rolling_chain_hash: self.rolling_chain_hash,
            signed_head_hash: signed_head,
        });
    }
}

// ---------------------------------------------------------------------------
// Hash computation
// ---------------------------------------------------------------------------

/// Compute the ContentHash for a marker from its content fields.
fn compute_marker_hash(marker: &DecisionMarker) -> ContentHash {
    let mut preimage = Vec::new();

    preimage.extend_from_slice(&marker.marker_id.to_be_bytes());
    preimage.extend_from_slice(marker.prev_marker_hash.as_bytes());
    preimage.extend_from_slice(&marker.timestamp_ticks.to_be_bytes());
    preimage.extend_from_slice(&marker.epoch_id.to_be_bytes());

    // Decision type as deterministic string.
    let dt_str = marker.decision_type.to_string();
    preimage.extend_from_slice(&(dt_str.len() as u32).to_be_bytes());
    preimage.extend_from_slice(dt_str.as_bytes());

    preimage.extend_from_slice(&(marker.decision_id.len() as u32).to_be_bytes());
    preimage.extend_from_slice(marker.decision_id.as_bytes());

    match &marker.policy_id {
        Some(policy_id) => {
            preimage.push(1);
            preimage.extend_from_slice(&(policy_id.len() as u32).to_be_bytes());
            preimage.extend_from_slice(policy_id.as_bytes());
        }
        None => preimage.push(0),
    }

    preimage.extend_from_slice(&(marker.correlation_id.as_str().len() as u32).to_be_bytes());
    preimage.extend_from_slice(marker.correlation_id.as_str().as_bytes());

    if let Some(trace_context) = &marker.trace_context {
        preimage.push(1);
        preimage.extend_from_slice(&(trace_context.traceparent.len() as u32).to_be_bytes());
        preimage.extend_from_slice(trace_context.traceparent.as_bytes());
        if let Some(tracestate) = &trace_context.tracestate {
            preimage.push(1);
            preimage.extend_from_slice(&(tracestate.len() as u32).to_be_bytes());
            preimage.extend_from_slice(tracestate.as_bytes());
        } else {
            preimage.push(0);
        }
        if let Some(baggage) = &trace_context.baggage {
            preimage.push(1);
            preimage.extend_from_slice(&(baggage.len() as u32).to_be_bytes());
            preimage.extend_from_slice(baggage.as_bytes());
        } else {
            preimage.push(0);
        }
    } else {
        preimage.push(0);
    }

    append_optional_string(&mut preimage, marker.principal_id.as_deref());
    append_optional_string(&mut preimage, marker.zone_id.as_deref());
    append_optional_string(&mut preimage, marker.error_code.as_deref());

    preimage.extend_from_slice(marker.evidence_entry_hash.as_bytes());

    preimage.extend_from_slice(&(marker.actor.len() as u32).to_be_bytes());
    preimage.extend_from_slice(marker.actor.as_bytes());

    preimage
        .extend_from_slice(&(marker.redacted_payload.redacted_summary.len() as u32).to_be_bytes());
    preimage.extend_from_slice(marker.redacted_payload.redacted_summary.as_bytes());
    preimage.extend_from_slice(marker.redacted_payload.payload_hash.as_bytes());
    preimage.push(u8::from(marker.redacted_payload.redaction_applied));

    ContentHash::compute(&preimage)
}

fn append_optional_string(preimage: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        preimage.push(1);
        preimage.extend_from_slice(&(value.len() as u32).to_be_bytes());
        preimage.extend_from_slice(value.as_bytes());
    } else {
        preimage.push(0);
    }
}

fn compute_rolling_hash(
    previous_rolling_hash: &ContentHash,
    marker_id: u64,
    marker_hash: &ContentHash,
) -> ContentHash {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(previous_rolling_hash.as_bytes());
    preimage.extend_from_slice(&marker_id.to_be_bytes());
    preimage.extend_from_slice(marker_hash.as_bytes());
    ContentHash::compute(&preimage)
}

fn recompute_rolling_hash(markers: &[DecisionMarker]) -> ContentHash {
    markers
        .iter()
        .fold(ContentHash([0u8; 32]), |rolling, marker| {
            compute_rolling_hash(&rolling, marker.marker_id, &marker.marker_hash)
        })
}

fn sign_chain_head(
    checkpoint_key: &[u8],
    marker_id: u64,
    latest_marker_hash: &ContentHash,
    rolling_chain_hash: &ContentHash,
) -> AuthenticityHash {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&marker_id.to_be_bytes());
    preimage.extend_from_slice(latest_marker_hash.as_bytes());
    preimage.extend_from_slice(rolling_chain_hash.as_bytes());
    AuthenticityHash::compute_keyed(checkpoint_key, &preimage)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_evidence_hash() -> ContentHash {
        ContentHash::compute(b"evidence-entry-content")
    }

    fn make_stream() -> DecisionMarkerStream {
        DecisionMarkerStream::new(5, b"test-checkpoint-key".to_vec())
    }

    fn make_input(decision_type: DecisionType) -> MarkerInput {
        MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type,
            decision_id: "decision-test".to_string(),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new("corr-test").expect("valid correlation id"),
            trace_context: None,
            principal_id: Some("principal-operator".to_string()),
            zone_id: Some("zone-a".to_string()),
            error_code: None,
            evidence_entry_hash: test_evidence_hash(),
            actor: "operator".to_string(),
            payload_summary: "summary".to_string(),
            full_payload: None,
            trace_id: "trace-test".to_string(),
        }
    }

    fn security_input(id_suffix: &str) -> MarkerInput {
        MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            decision_id: format!("decision-{id_suffix}"),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new(format!("corr-{id_suffix}"))
                .expect("valid correlation id"),
            trace_context: None,
            principal_id: Some("principal-operator".to_string()),
            zone_id: Some("zone-a".to_string()),
            error_code: None,
            evidence_entry_hash: test_evidence_hash(),
            actor: "operator".to_string(),
            payload_summary: "quarantine target-x".to_string(),
            full_payload: None,
            trace_id: format!("trace-{id_suffix}"),
        }
    }

    fn append_security_marker(stream: &mut DecisionMarkerStream, id_suffix: &str) {
        stream.append(security_input(id_suffix));
    }

    // -- Basic append --

    #[test]
    fn append_creates_marker_with_correct_id() {
        let mut stream = make_stream();
        let marker = stream.append(MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            decision_id: "dec-1".to_string(),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new("corr-basic").expect("valid correlation id"),
            trace_context: None,
            principal_id: None,
            zone_id: None,
            error_code: None,
            evidence_entry_hash: test_evidence_hash(),
            actor: "operator".to_string(),
            payload_summary: "quarantine ext-abc".to_string(),
            full_payload: None,
            trace_id: "trace-1".to_string(),
        });
        assert_eq!(marker.marker_id, 1);
        assert_eq!(marker.epoch_id, 1);
        assert_eq!(marker.actor, "operator");
    }

    #[test]
    fn sequential_appends_increment_ids() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");
        append_security_marker(&mut stream, "3");
        assert_eq!(stream.len(), 3);
        assert_eq!(stream.markers()[0].marker_id, 1);
        assert_eq!(stream.markers()[1].marker_id, 2);
        assert_eq!(stream.markers()[2].marker_id, 3);
    }

    // -- Hash chain --

    #[test]
    fn genesis_marker_has_zero_prev_hash() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        assert_eq!(stream.markers()[0].prev_marker_hash, ContentHash([0u8; 32]));
    }

    #[test]
    fn subsequent_markers_chain_to_previous() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");

        let m1 = &stream.markers()[0];
        let m2 = &stream.markers()[1];
        assert_eq!(m2.prev_marker_hash, m1.marker_hash);
    }

    #[test]
    fn hash_chain_is_deterministic() {
        let run = || {
            let mut stream = make_stream();
            for i in 0..5 {
                append_security_marker(&mut stream, &i.to_string());
            }
            stream
                .markers()
                .iter()
                .map(|m| m.marker_hash)
                .collect::<Vec<_>>()
        };

        let hashes1 = run();
        let hashes2 = run();
        assert_eq!(hashes1, hashes2);
    }

    // -- Chain verification --

    #[test]
    fn verify_chain_succeeds_on_valid_stream() {
        let mut stream = make_stream();
        for i in 0..10 {
            append_security_marker(&mut stream, &i.to_string());
        }
        assert!(stream.verify_chain().is_ok());
    }

    #[test]
    fn verify_chain_fails_on_empty_stream() {
        let stream = make_stream();
        assert!(matches!(
            stream.verify_chain(),
            Err(ChainIntegrityError::EmptyStream)
        ));
    }

    #[test]
    fn verify_chain_detects_tampered_marker() {
        let mut stream = make_stream();
        for i in 0..5 {
            append_security_marker(&mut stream, &i.to_string());
        }

        // Tamper with a marker's payload.
        stream.markers[2].redacted_payload.redacted_summary = "tampered!".to_string();

        let err = stream.verify_chain().unwrap_err();
        assert!(matches!(
            err,
            ChainIntegrityError::MarkerHashMismatch { marker_id: 3, .. }
        ));
    }

    #[test]
    fn verify_chain_detects_broken_link() {
        let mut stream = make_stream();
        for i in 0..5 {
            append_security_marker(&mut stream, &i.to_string());
        }

        // Break the chain link by modifying prev_marker_hash.
        stream.markers[3].prev_marker_hash = ContentHash([0xff; 32]);

        let err = stream.verify_chain().unwrap_err();
        assert!(matches!(
            err,
            ChainIntegrityError::ChainLinkBroken { marker_id: 4, .. }
        ));
    }

    // -- Range verification --

    #[test]
    fn verify_range_succeeds_on_valid_subrange() {
        let mut stream = make_stream();
        for i in 0..10 {
            append_security_marker(&mut stream, &i.to_string());
        }
        assert!(stream.verify_range(3, 7).is_ok());
    }

    // -- Checkpoints --

    #[test]
    fn checkpoint_emitted_at_interval() {
        let mut stream = DecisionMarkerStream::new(3, b"key".to_vec());
        for i in 0..6 {
            append_security_marker(&mut stream, &i.to_string());
        }
        // Checkpoints at markers 3 and 6.
        assert_eq!(stream.checkpoints().len(), 2);
        assert_eq!(stream.checkpoints()[0].at_marker_id, 3);
        assert_eq!(stream.checkpoints()[1].at_marker_id, 6);
    }

    #[test]
    fn checkpoint_contains_signed_hash() {
        let mut stream = DecisionMarkerStream::new(2, b"test-key".to_vec());
        for i in 0..4 {
            append_security_marker(&mut stream, &i.to_string());
        }
        assert!(!stream.checkpoints().is_empty());
        // Signed hash should not be all zeros.
        let cp = &stream.checkpoints()[0];
        assert_ne!(cp.signed_hash.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn checkpoint_is_deterministic() {
        let run = || {
            let mut stream = DecisionMarkerStream::new(2, b"key".to_vec());
            for i in 0..4 {
                append_security_marker(&mut stream, &i.to_string());
            }
            stream.checkpoints().to_vec()
        };
        let cp1 = run();
        let cp2 = run();
        assert_eq!(cp1, cp2);
    }

    // -- Decision types --

    #[test]
    fn all_decision_types_produce_valid_markers() {
        let mut stream = make_stream();
        let types = [
            DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            DecisionType::SecurityAction {
                action: SecurityActionKind::Suspend,
            },
            DecisionType::SecurityAction {
                action: SecurityActionKind::Terminate,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Activation,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Deactivation,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::EpochAdvancement,
            },
            DecisionType::RevocationEvent {
                revocation: RevocationKind::Issuance,
            },
            DecisionType::RevocationEvent {
                revocation: RevocationKind::PropagationConfirmation,
            },
            DecisionType::EpochTransition {
                from_epoch: 1,
                to_epoch: 2,
            },
            DecisionType::EmergencyOverride {
                override_reason: "critical".to_string(),
            },
            DecisionType::GuardrailTriggered {
                guardrail_id: "grd-1".to_string(),
            },
        ];

        for (i, dt) in types.into_iter().enumerate() {
            stream.append(MarkerInput {
                timestamp_ticks: i as u64 * 10,
                epoch_id: 1,
                decision_type: dt,
                decision_id: format!("dec-{i}"),
                policy_id: Some("policy-default".to_string()),
                correlation_id: CorrelationId::new(format!("corr-all-{i}"))
                    .expect("valid correlation id"),
                trace_context: None,
                principal_id: None,
                zone_id: None,
                error_code: if i.is_multiple_of(2) {
                    Some("FE-TEST-0001".to_string())
                } else {
                    None
                },
                evidence_entry_hash: test_evidence_hash(),
                actor: "system".to_string(),
                payload_summary: "test".to_string(),
                full_payload: None,
                trace_id: format!("trace-{i}"),
            });
        }

        assert_eq!(stream.len(), 11);
        assert!(stream.verify_chain().is_ok());
    }

    // -- Decision type display --

    #[test]
    fn decision_type_display() {
        assert!(
            DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine
            }
            .to_string()
            .contains("quarantine")
        );
        assert!(
            DecisionType::EpochTransition {
                from_epoch: 1,
                to_epoch: 2
            }
            .to_string()
            .contains("1->2")
        );
    }

    // -- Events --

    #[test]
    fn append_emits_events() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");

        let events = stream.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].marker_id, 1);
        assert_eq!(events[0].event, "marker_appended");
        assert_eq!(events[0].decision_id, "decision-1");
        assert_eq!(events[0].policy_id.as_deref(), Some("policy-default"));
        assert_eq!(
            events[0].principal_id.as_deref(),
            Some("principal-operator")
        );
        assert_eq!(events[1].marker_id, 2);
    }

    #[test]
    fn drain_events_clears() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        let events1 = stream.drain_events();
        assert_eq!(events1.len(), 1);
        let events2 = stream.drain_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn by_correlation_id_returns_related_markers() {
        let mut stream = make_stream();
        for (i, correlation) in ["corr-flow-a", "corr-flow-a", "corr-flow-b"]
            .iter()
            .enumerate()
        {
            stream.append(MarkerInput {
                timestamp_ticks: 100 + i as u64,
                epoch_id: 1,
                decision_type: DecisionType::SecurityAction {
                    action: SecurityActionKind::Quarantine,
                },
                decision_id: format!("dec-corr-{i}"),
                policy_id: Some("policy-default".to_string()),
                correlation_id: CorrelationId::new(*correlation).expect("valid correlation id"),
                trace_context: None,
                principal_id: None,
                zone_id: None,
                error_code: None,
                evidence_entry_hash: test_evidence_hash(),
                actor: "system".to_string(),
                payload_summary: "redacted".to_string(),
                full_payload: None,
                trace_id: format!("trace-corr-{i}"),
            });
        }

        assert_eq!(stream.by_correlation_id("corr-flow-a").len(), 2);
        assert_eq!(stream.by_correlation_id("corr-flow-b").len(), 1);
        assert!(stream.by_correlation_id("corr-missing").is_empty());
    }

    #[test]
    fn by_error_code_returns_only_matching_markers() {
        let mut stream = make_stream();
        stream.append(MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            decision_id: "dec-1".to_string(),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new("corr-err-1").expect("valid correlation id"),
            trace_context: None,
            principal_id: None,
            zone_id: None,
            error_code: Some("FE-TEST-1001".to_string()),
            evidence_entry_hash: test_evidence_hash(),
            actor: "system".to_string(),
            payload_summary: "redacted".to_string(),
            full_payload: None,
            trace_id: "trace-1".to_string(),
        });
        stream.append(MarkerInput {
            timestamp_ticks: 101,
            epoch_id: 1,
            decision_type: DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Activation,
            },
            decision_id: "dec-2".to_string(),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new("corr-err-2").expect("valid correlation id"),
            trace_context: None,
            principal_id: None,
            zone_id: None,
            error_code: None,
            evidence_entry_hash: test_evidence_hash(),
            actor: "system".to_string(),
            payload_summary: "redacted".to_string(),
            full_payload: None,
            trace_id: "trace-2".to_string(),
        });

        assert_eq!(stream.by_error_code("FE-TEST-1001").len(), 1);
        assert!(stream.by_error_code("FE-TEST-9999").is_empty());
    }

    #[test]
    fn by_principal_id_returns_only_matching_markers() {
        let mut stream = make_stream();
        stream.append(MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            decision_id: "dec-principal-1".to_string(),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new("corr-principal-1").expect("valid correlation id"),
            trace_context: None,
            principal_id: Some("principal-a".to_string()),
            zone_id: None,
            error_code: None,
            evidence_entry_hash: test_evidence_hash(),
            actor: "system".to_string(),
            payload_summary: "redacted".to_string(),
            full_payload: None,
            trace_id: "trace-principal-1".to_string(),
        });
        stream.append(MarkerInput {
            timestamp_ticks: 101,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Suspend,
            },
            decision_id: "dec-principal-2".to_string(),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new("corr-principal-2").expect("valid correlation id"),
            trace_context: None,
            principal_id: Some("principal-b".to_string()),
            zone_id: None,
            error_code: None,
            evidence_entry_hash: test_evidence_hash(),
            actor: "system".to_string(),
            payload_summary: "redacted".to_string(),
            full_payload: None,
            trace_id: "trace-principal-2".to_string(),
        });

        assert_eq!(stream.by_principal_id("principal-a").len(), 1);
        assert_eq!(stream.by_principal_id("principal-b").len(), 1);
        assert!(stream.by_principal_id("principal-missing").is_empty());
    }

    #[test]
    fn by_time_range_returns_only_inclusive_matches() {
        let mut stream = make_stream();
        for i in 0..4 {
            stream.append(MarkerInput {
                timestamp_ticks: 100 + i * 10,
                epoch_id: 1,
                decision_type: DecisionType::SecurityAction {
                    action: SecurityActionKind::Quarantine,
                },
                decision_id: format!("dec-time-{i}"),
                policy_id: Some("policy-default".to_string()),
                correlation_id: CorrelationId::new(format!("corr-time-{i}"))
                    .expect("valid correlation id"),
                trace_context: None,
                principal_id: None,
                zone_id: None,
                error_code: None,
                evidence_entry_hash: test_evidence_hash(),
                actor: "system".to_string(),
                payload_summary: "redacted".to_string(),
                full_payload: None,
                trace_id: format!("trace-time-{i}"),
            });
        }

        let in_range = stream.by_time_range(110, 120);
        assert_eq!(in_range.len(), 2);
        assert_eq!(in_range[0].timestamp_ticks, 110);
        assert_eq!(in_range[1].timestamp_ticks, 120);
    }

    #[test]
    fn integration_flow_links_related_events_by_correlation_id() {
        let mut stream = make_stream();
        let correlation_id = CorrelationId::new("corr-integration").expect("valid correlation id");
        let flow = [
            DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            DecisionType::RevocationEvent {
                revocation: RevocationKind::Issuance,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Activation,
            },
        ];

        for (i, decision_type) in flow.into_iter().enumerate() {
            stream.append(MarkerInput {
                timestamp_ticks: 1_000 + i as u64,
                epoch_id: 7,
                decision_type,
                decision_id: format!("dec-integration-{i}"),
                policy_id: Some("policy-integration".to_string()),
                correlation_id: correlation_id.clone(),
                trace_context: Some(TraceContext {
                    traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
                        .to_string(),
                    tracestate: Some("vendor=value".to_string()),
                    baggage: Some("tenant=alpha".to_string()),
                }),
                principal_id: Some("principal-integration".to_string()),
                zone_id: Some("zone-integration".to_string()),
                error_code: None,
                evidence_entry_hash: test_evidence_hash(),
                actor: "runtime".to_string(),
                payload_summary: "[redacted]".to_string(),
                full_payload: Some(format!("sensitive-flow-{i}")),
                trace_id: "trace-integration".to_string(),
            });
        }

        assert_eq!(stream.by_correlation_id("corr-integration").len(), 3);
        assert_eq!(stream.by_principal_id("principal-integration").len(), 3);
        assert!(stream.verify_chain().is_ok());
        assert!(stream.verify_head().is_ok());

        let events = stream.drain_events();
        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .all(|event| event.trace_id == "trace-integration")
        );
        assert!(
            events
                .iter()
                .all(|event| event.policy_id.as_deref() == Some("policy-integration"))
        );
    }

    #[test]
    fn chain_head_advances_and_verifies() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");

        let head = stream.chain_head().expect("head should exist");
        assert_eq!(head.head_marker_id, 2);
        assert!(stream.verify_head().is_ok());
    }

    #[test]
    fn payload_is_redacted_by_default_but_hashes_full_payload() {
        let mut stream = make_stream();
        let full_payload = "secret-token-value";
        stream.append(MarkerInput {
            timestamp_ticks: 100,
            epoch_id: 1,
            decision_type: DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            decision_id: "dec-redact".to_string(),
            policy_id: Some("policy-default".to_string()),
            correlation_id: CorrelationId::new("corr-redact").expect("valid correlation id"),
            trace_context: Some(TraceContext {
                traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00".to_string(),
                tracestate: Some("vendor=value".to_string()),
                baggage: None,
            }),
            principal_id: Some("principal-redact".to_string()),
            zone_id: Some("zone-red".to_string()),
            error_code: None,
            evidence_entry_hash: test_evidence_hash(),
            actor: "system".to_string(),
            payload_summary: "[redacted]".to_string(),
            full_payload: Some(full_payload.to_string()),
            trace_id: "trace-redact".to_string(),
        });

        let marker = stream.get(1).expect("marker exists");
        assert!(marker.redacted_payload.redaction_applied);
        assert_eq!(marker.redacted_payload.redacted_summary, "[redacted]");
        assert_eq!(
            marker.redacted_payload.payload_hash,
            ContentHash::compute(full_payload.as_bytes())
        );
        assert!(
            !marker
                .redacted_payload
                .redacted_summary
                .contains("secret-token-value")
        );
    }

    // -- Get marker by ID --

    #[test]
    fn get_existing_marker() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        append_security_marker(&mut stream, "2");

        let m = stream.get(2).unwrap();
        assert_eq!(m.marker_id, 2);
    }

    #[test]
    fn get_nonexistent_marker_returns_none() {
        let stream = make_stream();
        assert!(stream.get(999).is_none());
    }

    // -- Serialization --

    #[test]
    fn decision_marker_serialization_round_trip() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");

        let marker = &stream.markers()[0];
        let json = serde_json::to_string(marker).expect("serialize");
        let restored: DecisionMarker = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*marker, restored);
    }

    #[test]
    fn integrity_checkpoint_serialization_round_trip() {
        let cp = IntegrityCheckpoint {
            at_marker_id: 10,
            marker_hash: ContentHash::compute(b"test"),
            chain_length: 10,
            signed_hash: AuthenticityHash::compute_keyed(b"key", b"data"),
        };
        let json = serde_json::to_string(&cp).expect("serialize");
        let restored: IntegrityCheckpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cp, restored);
    }

    #[test]
    fn chain_integrity_error_serialization_round_trip() {
        let errors = [
            ChainIntegrityError::EmptyStream,
            ChainIntegrityError::NonMonotonicId {
                marker_id: 5,
                prev_marker_id: 6,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ChainIntegrityError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn marker_event_serialization_round_trip() {
        let event = MarkerEvent {
            marker_id: 1,
            marker_type: "security_action".to_string(),
            chain_length: 1,
            decision_id: "dec-1".to_string(),
            policy_id: Some("policy-default".to_string()),
            principal_id: Some("principal-1".to_string()),
            correlation_id: "corr-1".to_string(),
            trace_id: "trace-1".to_string(),
            component: "marker_stream".to_string(),
            event: "marker_appended".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: MarkerEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Error display --

    #[test]
    fn chain_integrity_error_display() {
        assert_eq!(ChainIntegrityError::EmptyStream.to_string(), "empty stream");
        assert!(
            ChainIntegrityError::MarkerHashMismatch {
                marker_id: 5,
                expected: ContentHash([0; 32]),
                computed: ContentHash([1; 32]),
            }
            .to_string()
            .contains("5")
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn security_action_kind_serde_roundtrip() {
        for v in [
            SecurityActionKind::Quarantine,
            SecurityActionKind::Suspend,
            SecurityActionKind::Terminate,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: SecurityActionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn policy_transition_kind_serde_roundtrip() {
        for v in [
            PolicyTransitionKind::Activation,
            PolicyTransitionKind::Deactivation,
            PolicyTransitionKind::EpochAdvancement,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: PolicyTransitionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn revocation_kind_serde_roundtrip() {
        for v in [
            RevocationKind::Issuance,
            RevocationKind::PropagationConfirmation,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: RevocationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn correlation_id_serde_roundtrip() {
        let cid = CorrelationId::new("corr-123").unwrap();
        let json = serde_json::to_string(&cid).unwrap();
        let restored: CorrelationId = serde_json::from_str(&json).unwrap();
        assert_eq!(cid, restored);
    }

    #[test]
    fn trace_context_serde_roundtrip() {
        let tc = TraceContext {
            traceparent: "00-abc-def-01".to_string(),
            tracestate: Some("vendor=val".to_string()),
            baggage: None,
        };
        let json = serde_json::to_string(&tc).unwrap();
        let restored: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, restored);
    }

    #[test]
    fn redacted_payload_serde_roundtrip() {
        let rp = RedactedPayload {
            redacted_summary: "summary".to_string(),
            payload_hash: ContentHash::compute(b"payload"),
            redaction_applied: true,
        };
        let json = serde_json::to_string(&rp).unwrap();
        let restored: RedactedPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(rp, restored);
    }

    #[test]
    fn audit_chain_head_serde_roundtrip() {
        let head = AuditChainHead {
            head_marker_id: 42,
            latest_marker_hash: ContentHash::compute(b"latest"),
            rolling_chain_hash: ContentHash::compute(b"rolling"),
            signed_head_hash: AuthenticityHash::compute_keyed(b"head", b"key"),
        };
        let json = serde_json::to_string(&head).unwrap();
        let restored: AuditChainHead = serde_json::from_str(&json).unwrap();
        assert_eq!(head, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn security_action_kind_ordering() {
        assert!(SecurityActionKind::Quarantine < SecurityActionKind::Terminate);
    }

    #[test]
    fn policy_transition_kind_ordering() {
        assert!(PolicyTransitionKind::Activation < PolicyTransitionKind::EpochAdvancement);
    }

    #[test]
    fn revocation_kind_ordering() {
        assert!(RevocationKind::Issuance < RevocationKind::PropagationConfirmation);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display content for sub-kinds
    // -----------------------------------------------------------------------

    #[test]
    fn security_action_kind_display_all() {
        assert_eq!(SecurityActionKind::Quarantine.to_string(), "quarantine");
        assert_eq!(SecurityActionKind::Suspend.to_string(), "suspend");
        assert_eq!(SecurityActionKind::Terminate.to_string(), "terminate");
    }

    #[test]
    fn policy_transition_kind_display_all() {
        assert_eq!(PolicyTransitionKind::Activation.to_string(), "activation");
        assert_eq!(
            PolicyTransitionKind::Deactivation.to_string(),
            "deactivation"
        );
        assert_eq!(
            PolicyTransitionKind::EpochAdvancement.to_string(),
            "epoch_advancement"
        );
    }

    #[test]
    fn revocation_kind_display_all() {
        assert_eq!(RevocationKind::Issuance.to_string(), "issuance");
        assert_eq!(
            RevocationKind::PropagationConfirmation.to_string(),
            "propagation_confirmation"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: CorrelationId helpers
    // -----------------------------------------------------------------------

    #[test]
    fn correlation_id_as_str_matches_display() {
        let cid = CorrelationId::new("corr-x").unwrap();
        assert_eq!(cid.as_str(), "corr-x");
        assert_eq!(cid.to_string(), "corr-x");
    }

    // -----------------------------------------------------------------------
    // Enrichment: ChainIntegrityError is std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn chain_integrity_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ChainIntegrityError::EmptyStream);
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment batch 3: clone, determinism, field presence, edge cases --

    #[test]
    fn decision_marker_clone_equality() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        let marker = stream.markers()[0].clone();
        let cloned = marker.clone();
        assert_eq!(marker, cloned);
    }

    #[test]
    fn integrity_checkpoint_clone_equality() {
        let cp = IntegrityCheckpoint {
            at_marker_id: 5,
            marker_hash: ContentHash::compute(b"test"),
            chain_length: 5,
            signed_hash: AuthenticityHash::compute_keyed(b"k", b"d"),
        };
        assert_eq!(cp, cp.clone());
    }

    #[test]
    fn chain_head_on_empty_stream_is_none() {
        let stream = make_stream();
        assert!(stream.chain_head().is_none());
    }

    #[test]
    fn marker_ids_monotonically_increase() {
        let mut stream = make_stream();
        for i in 0..5 {
            append_security_marker(&mut stream, &i.to_string());
        }
        let ids: Vec<u64> = stream.markers().iter().map(|m| m.marker_id).collect();
        for pair in ids.windows(2) {
            assert!(pair[0] < pair[1], "IDs must be strictly increasing");
        }
    }

    #[test]
    fn marker_json_field_presence() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        let json = serde_json::to_string(&stream.markers()[0]).unwrap();
        for field in &[
            "marker_id",
            "timestamp_ticks",
            "epoch_id",
            "decision_type",
            "decision_id",
            "correlation_id",
            "evidence_entry_hash",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn stream_deterministic_across_two_runs() {
        let run = || {
            let mut stream = DecisionMarkerStream::new(5, b"det-key".to_vec());
            for i in 0..3 {
                append_security_marker(&mut stream, &i.to_string());
            }
            stream
                .markers()
                .iter()
                .map(|m| m.marker_hash)
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn marker_event_clone_equality() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "1");
        let events = stream.drain_events();
        assert!(!events.is_empty());
        let ev = &events[0];
        assert_eq!(*ev, ev.clone());
    }

    #[test]
    fn chain_integrity_error_display_uniqueness() {
        let errors = [
            ChainIntegrityError::EmptyStream,
            ChainIntegrityError::NonMonotonicId {
                marker_id: 2,
                prev_marker_id: 3,
            },
            ChainIntegrityError::MarkerHashMismatch {
                marker_id: 1,
                expected: ContentHash([0; 32]),
                computed: ContentHash([1; 32]),
            },
            ChainIntegrityError::ChainLinkBroken {
                marker_id: 1,
                expected_prev: ContentHash([0; 32]),
                actual_prev: ContentHash([1; 32]),
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            errors.len(),
            "all ChainIntegrityError variants must have unique Display"
        );
    }

    #[test]
    fn decision_type_serde_all_variants() {
        let variants = [
            DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Activation,
            },
            DecisionType::RevocationEvent {
                revocation: RevocationKind::Issuance,
            },
            DecisionType::EpochTransition {
                from_epoch: 1,
                to_epoch: 2,
            },
            DecisionType::EmergencyOverride {
                override_reason: "test".to_string(),
            },
            DecisionType::GuardrailTriggered {
                guardrail_id: "g1".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DecisionType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn decision_type_clone_equality() {
        let dt = DecisionType::EpochTransition {
            from_epoch: 10,
            to_epoch: 11,
        };
        assert_eq!(dt, dt.clone());
    }

    #[test]
    fn verify_chain_single_marker() {
        let mut stream = make_stream();
        append_security_marker(&mut stream, "single");
        assert!(stream.verify_chain().is_ok());
    }

    #[test]
    fn verify_empty_stream_returns_error() {
        let stream = make_stream();
        assert!(stream.verify_chain().is_err());
    }

    #[test]
    fn correlation_id_empty_rejected() {
        assert!(CorrelationId::new("").is_err());
    }

    // ── enrichment tests ────────────────────────────────────

    #[test]
    fn correlation_id_too_long_rejected() {
        let long = "a".repeat(129);
        assert!(CorrelationId::new(long).is_err());
    }

    #[test]
    fn correlation_id_exactly_128_accepted() {
        let exact = "b".repeat(128);
        assert!(CorrelationId::new(exact).is_ok());
    }

    #[test]
    fn correlation_id_unsupported_chars_rejected() {
        assert!(CorrelationId::new("hello world").is_err()); // space
        assert!(CorrelationId::new("abc@def").is_err()); // @
    }

    #[test]
    fn correlation_id_allowed_special_chars() {
        assert!(CorrelationId::new("abc-def_ghi.123").is_ok());
    }

    #[test]
    fn correlation_id_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let a = CorrelationId::new("trace-1").unwrap();
        let b = CorrelationId::new("trace-1").unwrap();
        let mut ha = std::collections::hash_map::DefaultHasher::new();
        let mut hb = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn correlation_id_hash_distinct() {
        use std::hash::{Hash, Hasher};
        let a = CorrelationId::new("trace-1").unwrap();
        let b = CorrelationId::new("trace-2").unwrap();
        let mut ha = std::collections::hash_map::DefaultHasher::new();
        let mut hb = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_ne!(ha.finish(), hb.finish());
    }

    #[test]
    fn correlation_id_ord_consistent() {
        let a = CorrelationId::new("aaa").unwrap();
        let b = CorrelationId::new("bbb").unwrap();
        assert!(a < b);
    }

    #[test]
    fn security_action_kind_debug_distinct() {
        let variants = [
            SecurityActionKind::Quarantine,
            SecurityActionKind::Suspend,
            SecurityActionKind::Terminate,
        ];
        let dbgs: Vec<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        for (i, a) in dbgs.iter().enumerate() {
            assert!(!a.is_empty());
            for (j, b) in dbgs.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn policy_transition_kind_debug_distinct() {
        let variants = [
            PolicyTransitionKind::Activation,
            PolicyTransitionKind::Deactivation,
            PolicyTransitionKind::EpochAdvancement,
        ];
        let dbgs: Vec<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        for (i, a) in dbgs.iter().enumerate() {
            for (j, b) in dbgs.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn revocation_kind_debug_distinct() {
        let a = format!("{:?}", RevocationKind::Issuance);
        let b = format!("{:?}", RevocationKind::PropagationConfirmation);
        assert_ne!(a, b);
    }

    #[test]
    fn chain_integrity_error_all_variants_serde_distinct() {
        let zero = ContentHash([0u8; 32]);
        let one = ContentHash([1u8; 32]);
        let variants = [
            ChainIntegrityError::MarkerHashMismatch {
                marker_id: 1,
                expected: zero,
                computed: one,
            },
            ChainIntegrityError::ChainLinkBroken {
                marker_id: 2,
                expected_prev: zero,
                actual_prev: one,
            },
            ChainIntegrityError::EmptyStream,
            ChainIntegrityError::NonMonotonicId {
                marker_id: 1,
                prev_marker_id: 5,
            },
            ChainIntegrityError::HeadMismatch,
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for (i, a) in jsons.iter().enumerate() {
            for (j, b) in jsons.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} collide");
                }
            }
        }
    }

    #[test]
    fn chain_integrity_error_clone_independence() {
        let e = ChainIntegrityError::MarkerHashMismatch {
            marker_id: 42,
            expected: ContentHash([0u8; 32]),
            computed: ContentHash([1u8; 32]),
        };
        let cloned = e.clone();
        assert_eq!(e, cloned);
        // Both are independent allocations
        let j1 = serde_json::to_string(&e).unwrap();
        let j2 = serde_json::to_string(&cloned).unwrap();
        assert_eq!(j1, j2);
    }

    #[test]
    fn trace_context_clone_independence() {
        let t = TraceContext {
            traceparent: "00-abc-def-01".to_string(),
            tracestate: Some("vendor=value".to_string()),
            baggage: None,
        };
        let mut cloned = t.clone();
        cloned.traceparent = "changed".to_string();
        assert_eq!(t.traceparent, "00-abc-def-01");
    }

    #[test]
    fn trace_context_json_field_names() {
        let t = TraceContext {
            traceparent: "tp".to_string(),
            tracestate: Some("ts".to_string()),
            baggage: Some("bg".to_string()),
        };
        let j = serde_json::to_string(&t).unwrap();
        assert!(j.contains("\"traceparent\""));
        assert!(j.contains("\"tracestate\""));
        assert!(j.contains("\"baggage\""));
    }

    #[test]
    fn redacted_payload_json_field_names() {
        let r = RedactedPayload {
            redacted_summary: "s".to_string(),
            payload_hash: ContentHash([0u8; 32]),
            redaction_applied: true,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"redacted_summary\""));
        assert!(j.contains("\"payload_hash\""));
        assert!(j.contains("\"redaction_applied\""));
    }

    #[test]
    fn redacted_payload_clone_independence() {
        let r = RedactedPayload {
            redacted_summary: "original".to_string(),
            payload_hash: ContentHash([5u8; 32]),
            redaction_applied: false,
        };
        let mut cloned = r.clone();
        cloned.redacted_summary = "modified".to_string();
        assert_eq!(r.redacted_summary, "original");
    }

    #[test]
    fn integrity_checkpoint_json_field_names() {
        let c = IntegrityCheckpoint {
            at_marker_id: 5,
            marker_hash: ContentHash([0u8; 32]),
            chain_length: 5,
            signed_hash: AuthenticityHash([0u8; 32]),
        };
        let j = serde_json::to_string(&c).unwrap();
        for field in &["at_marker_id", "marker_hash", "chain_length", "signed_hash"] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn audit_chain_head_json_field_names() {
        let h = AuditChainHead {
            head_marker_id: 1,
            latest_marker_hash: ContentHash([0u8; 32]),
            rolling_chain_hash: ContentHash([0u8; 32]),
            signed_head_hash: AuthenticityHash([0u8; 32]),
        };
        let j = serde_json::to_string(&h).unwrap();
        for field in &[
            "head_marker_id",
            "latest_marker_hash",
            "rolling_chain_hash",
            "signed_head_hash",
        ] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn audit_chain_head_clone_independence() {
        let h = AuditChainHead {
            head_marker_id: 10,
            latest_marker_hash: ContentHash([1u8; 32]),
            rolling_chain_hash: ContentHash([2u8; 32]),
            signed_head_hash: AuthenticityHash([3u8; 32]),
        };
        let cloned = h.clone();
        assert_eq!(h, cloned);
    }

    #[test]
    fn marker_event_json_field_names() {
        let e = MarkerEvent {
            marker_id: 1,
            marker_type: "security".to_string(),
            chain_length: 1,
            decision_id: "d".to_string(),
            policy_id: None,
            principal_id: None,
            correlation_id: "c".to_string(),
            trace_id: "t".to_string(),
            component: "marker_stream".to_string(),
            event: "appended".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let j = serde_json::to_string(&e).unwrap();
        for field in &[
            "marker_id",
            "marker_type",
            "chain_length",
            "decision_id",
            "correlation_id",
            "trace_id",
            "component",
            "event",
            "outcome",
        ] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn decision_type_epoch_display_format() {
        let d = DecisionType::EpochTransition {
            from_epoch: 3,
            to_epoch: 4,
        };
        assert_eq!(d.to_string(), "epoch_transition:3->4");
    }

    #[test]
    fn decision_type_emergency_override_display() {
        let d = DecisionType::EmergencyOverride {
            override_reason: "test-reason".to_string(),
        };
        assert_eq!(d.to_string(), "emergency_override");
    }

    #[test]
    fn decision_type_guardrail_display() {
        let d = DecisionType::GuardrailTriggered {
            guardrail_id: "g-1".to_string(),
        };
        assert_eq!(d.to_string(), "guardrail_triggered:g-1");
    }

    #[test]
    fn by_event_type_filters_correctly() {
        let mut stream = make_stream();
        let input1 = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        let input2 = make_input(DecisionType::EmergencyOverride {
            override_reason: "test".to_string(),
        });
        stream.append(input1);
        stream.append(input2);
        let results = stream.by_event_type("security_action:quarantine");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn by_time_range_empty_when_no_match() {
        let mut stream = make_stream();
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Suspend,
        });
        stream.append(input);
        // All markers have timestamp_ticks=100, so 200..300 should be empty
        let results = stream.by_time_range(200, 300);
        assert!(results.is_empty());
    }

    #[test]
    fn verify_head_on_single_marker_stream() {
        let mut stream = make_stream();
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Terminate,
        });
        stream.append(input);
        assert!(stream.verify_head().is_ok());
    }

    #[test]
    fn verify_head_on_empty_stream_ok() {
        let stream = make_stream();
        assert!(stream.verify_head().is_ok());
    }

    #[test]
    fn verify_range_invalid_ids_returns_empty_stream_error() {
        let mut stream = make_stream();
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        stream.append(input);
        let result = stream.verify_range(999, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn non_monotonic_id_display_format() {
        let e = ChainIntegrityError::NonMonotonicId {
            marker_id: 3,
            prev_marker_id: 7,
        };
        assert_eq!(e.to_string(), "non-monotonic: 3 after 7");
    }

    #[test]
    fn head_mismatch_display_format() {
        let e = ChainIntegrityError::HeadMismatch;
        assert_eq!(e.to_string(), "chain head mismatch");
    }

    #[test]
    fn empty_stream_display_format() {
        let e = ChainIntegrityError::EmptyStream;
        assert_eq!(e.to_string(), "empty stream");
    }

    #[test]
    fn marker_hash_mismatch_display_contains_id() {
        let e = ChainIntegrityError::MarkerHashMismatch {
            marker_id: 42,
            expected: ContentHash([0u8; 32]),
            computed: ContentHash([1u8; 32]),
        };
        let s = e.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("hash mismatch"));
    }

    #[test]
    fn chain_link_broken_display_contains_id() {
        let e = ChainIntegrityError::ChainLinkBroken {
            marker_id: 99,
            expected_prev: ContentHash([0u8; 32]),
            actual_prev: ContentHash([1u8; 32]),
        };
        let s = e.to_string();
        assert!(s.contains("99"));
        assert!(s.contains("chain link broken"));
    }

    #[test]
    fn stream_len_and_is_empty() {
        let mut stream = make_stream();
        assert_eq!(stream.len(), 0);
        assert!(stream.is_empty());
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        stream.append(input);
        assert_eq!(stream.len(), 1);
        assert!(!stream.is_empty());
    }

    #[test]
    fn decision_type_security_action_display_all_kinds() {
        for (kind, expected) in [
            (SecurityActionKind::Quarantine, "security_action:quarantine"),
            (SecurityActionKind::Suspend, "security_action:suspend"),
            (SecurityActionKind::Terminate, "security_action:terminate"),
        ] {
            let dt = DecisionType::SecurityAction { action: kind };
            assert_eq!(dt.to_string(), expected);
        }
    }

    #[test]
    fn decision_type_policy_transition_display_all_kinds() {
        for (kind, expected) in [
            (
                PolicyTransitionKind::Activation,
                "policy_transition:activation",
            ),
            (
                PolicyTransitionKind::Deactivation,
                "policy_transition:deactivation",
            ),
            (
                PolicyTransitionKind::EpochAdvancement,
                "policy_transition:epoch_advancement",
            ),
        ] {
            let dt = DecisionType::PolicyTransition { transition: kind };
            assert_eq!(dt.to_string(), expected);
        }
    }

    #[test]
    fn decision_type_revocation_event_display_all_kinds() {
        for (kind, expected) in [
            (RevocationKind::Issuance, "revocation_event:issuance"),
            (
                RevocationKind::PropagationConfirmation,
                "revocation_event:propagation_confirmation",
            ),
        ] {
            let dt = DecisionType::RevocationEvent { revocation: kind };
            assert_eq!(dt.to_string(), expected);
        }
    }

    #[test]
    fn multiple_checkpoints_emitted() {
        let mut stream = DecisionMarkerStream::new(2, b"key".to_vec());
        for _ in 0..4 {
            let input = make_input(DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            });
            stream.append(input);
        }
        // checkpoint_interval=2, so checkpoints at marker 2 and 4
        assert_eq!(stream.checkpoints().len(), 2);
    }

    #[test]
    fn chain_head_updates_on_each_append() {
        let mut stream = make_stream();
        let input1 = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        stream.append(input1);
        let head1 = stream.chain_head().unwrap().head_marker_id;
        let input2 = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Suspend,
        });
        stream.append(input2);
        let head2 = stream.chain_head().unwrap().head_marker_id;
        assert!(head2 > head1);
    }

    #[test]
    fn by_principal_id_empty_when_no_match() {
        let mut stream = make_stream();
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        stream.append(input);
        let results = stream.by_principal_id("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn by_error_code_empty_when_no_match() {
        let mut stream = make_stream();
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        stream.append(input);
        let results = stream.by_error_code("NONEXISTENT");
        assert!(results.is_empty());
    }

    #[test]
    fn decision_marker_debug_nonempty() {
        let mut stream = make_stream();
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        stream.append(input);
        let marker = stream.get(1).unwrap();
        let dbg = format!("{marker:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("DecisionMarker"));
    }

    #[test]
    fn marker_event_debug_nonempty() {
        let mut stream = make_stream();
        let input = make_input(DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        });
        stream.append(input);
        let events = stream.drain_events();
        assert!(!events.is_empty());
        let dbg = format!("{:?}", events[0]);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("MarkerEvent"));
    }

    #[test]
    fn decision_marker_stream_debug_nonempty() {
        let stream = make_stream();
        let dbg = format!("{stream:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("DecisionMarkerStream"));
    }
}
