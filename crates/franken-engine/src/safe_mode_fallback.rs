//! Fallback validation proving control-plane failure degrades to deterministic
//! safe mode rather than undefined behavior.
//!
//! When the control plane itself fails (adapter layer unavailable, decision
//! contract evaluation errors, evidence ledger full, Cx corrupted,
//! cancellation protocol deadlock), the extension-host subsystem must degrade
//! to a deterministic safe mode: observable, bounded, and recoverable.
//!
//! ## Failure Types and Safe Modes
//!
//! | Failure | Safe-Mode Response |
//! |---|---|
//! | Adapter unavailable | Refuse extensions; emit diagnostic |
//! | Decision contract error | Default-deny; quarantine requester |
//! | Evidence ledger full | Ring buffer fallback; block high-impact |
//! | Cx corrupted (budget underflow) | Reject current op; fresh Cx next op |
//! | Cancellation deadlock | Force-finalize after timeout |
//!
//! Plan reference: Section 10.13 item 18, bd-jaqy.
//! Dependencies: bd-23om (adapter layer), bd-3a5e (decision contracts),
//!               bd-uvmm (evidence emission).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::{
    ControlPlaneAdapterError, DecisionAdapter, DecisionRequest, DecisionVerdict,
};
use crate::receipt_verifier_pipeline::{
    UnifiedReceiptVerificationVerdict, VerificationFailureClass,
};
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignatureError, SigningKey, VerificationKey, sign_preimage,
    verify_signature,
};

// ---------------------------------------------------------------------------
// FailureType — classification of control-plane failures
// ---------------------------------------------------------------------------

/// Classification of control-plane failure that triggers safe-mode activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailureType {
    /// Adapter layer is unavailable (e.g., crate version mismatch at startup).
    AdapterUnavailable,
    /// Decision contract evaluation returned an error or unexpected result.
    DecisionContractError,
    /// Evidence ledger is full or unavailable for emission.
    EvidenceLedgerFull,
    /// Cx is corrupted (budget underflow, invalid trace_id, etc.).
    CxCorrupted,
    /// Cancellation protocol is stuck (drain timeout exceeded with no progress).
    CancellationDeadlock,
}

impl fmt::Display for FailureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdapterUnavailable => write!(f, "adapter_unavailable"),
            Self::DecisionContractError => write!(f, "decision_contract_error"),
            Self::EvidenceLedgerFull => write!(f, "evidence_ledger_full"),
            Self::CxCorrupted => write!(f, "cx_corrupted"),
            Self::CancellationDeadlock => write!(f, "cancellation_deadlock"),
        }
    }
}

// ---------------------------------------------------------------------------
// SafeModeAction — deterministic response to each failure type
// ---------------------------------------------------------------------------

/// Deterministic safe-mode response taken when a control-plane failure occurs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeModeAction {
    /// Refuse to load or activate any extensions until adapter is restored.
    RefuseExtensions { diagnostic: String },
    /// Default-deny the action and quarantine the requesting extension.
    DefaultDenyAndQuarantine {
        extension_id: String,
        reason: String,
    },
    /// Switch to bounded in-memory ring buffer for evidence; block high-impact
    /// actions until the ledger is restored.
    RingBufferFallback {
        capacity: usize,
        high_impact_blocked: bool,
    },
    /// Reject the current operation; issue a fresh Cx for the next operation.
    RejectAndRefreshCx {
        rejected_operation: String,
        corruption_detail: String,
    },
    /// Force-finalize the stuck cancellation after timeout.
    ForceFinalize { cell_id: String, timeout_ticks: u64 },
}

impl SafeModeAction {
    /// Returns the failure type this action corresponds to.
    pub fn failure_type(&self) -> FailureType {
        match self {
            Self::RefuseExtensions { .. } => FailureType::AdapterUnavailable,
            Self::DefaultDenyAndQuarantine { .. } => FailureType::DecisionContractError,
            Self::RingBufferFallback { .. } => FailureType::EvidenceLedgerFull,
            Self::RejectAndRefreshCx { .. } => FailureType::CxCorrupted,
            Self::ForceFinalize { .. } => FailureType::CancellationDeadlock,
        }
    }
}

// ---------------------------------------------------------------------------
// SafeModeEvent — structured event for safe-mode activation/recovery
// ---------------------------------------------------------------------------

/// Structured event emitted when safe mode activates or recovers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeEvent {
    /// Trace ID of the operation that triggered safe mode.
    pub trace_id: String,
    /// Type of failure that triggered safe mode.
    pub failure_type: FailureType,
    /// Phase: "activate" or "recover".
    pub phase: String,
    /// Action taken in safe mode (serialized for evidence).
    pub action_summary: String,
    /// Component that detected the failure.
    pub component: String,
    /// Outcome: "safe_mode_active", "recovery_complete", etc.
    pub outcome: String,
    /// Optional error code from the underlying failure.
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// RingBuffer — bounded in-memory evidence fallback
// ---------------------------------------------------------------------------

/// Bounded ring buffer for evidence entries when the primary ledger is full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRingBuffer {
    entries: Vec<RingBufferEntry>,
    capacity: usize,
    write_pos: usize,
    total_written: u64,
}

/// A single entry in the ring buffer fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingBufferEntry {
    pub trace_id: String,
    pub event: String,
    pub outcome: String,
    pub component: String,
    pub sequence: u64,
}

impl EvidenceRingBuffer {
    /// Create a ring buffer with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            write_pos: 0,
            total_written: 0,
        }
    }

    /// Push an entry into the ring buffer (overwrites oldest on overflow).
    pub fn push(&mut self, entry: RingBufferEntry) {
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
        } else {
            self.entries[self.write_pos] = entry;
        }
        self.write_pos = (self.write_pos + 1) % self.capacity;
        self.total_written = self.total_written.saturating_add(1);
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total entries ever written (including overwritten).
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// View stored entries in insertion order (oldest first).
    pub fn entries(&self) -> Vec<&RingBufferEntry> {
        if self.entries.len() < self.capacity {
            self.entries.iter().collect()
        } else {
            let mut result = Vec::with_capacity(self.capacity);
            for i in 0..self.capacity {
                let idx = (self.write_pos + i) % self.capacity;
                result.push(&self.entries[idx]);
            }
            result
        }
    }

    /// Drain all entries for recovery into primary ledger.
    pub fn drain(&mut self) -> Vec<RingBufferEntry> {
        self.write_pos = 0;
        std::mem::take(&mut self.entries)
    }
}

// ---------------------------------------------------------------------------
// SafeModeState — tracks current safe-mode activations
// ---------------------------------------------------------------------------

/// Current safe-mode state per failure type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SafeModeStatus {
    /// Normal operation (no safe mode active for this failure type).
    #[default]
    Normal,
    /// Safe mode is active for this failure type.
    Active,
    /// Recovering from safe mode (failure resolved, draining fallback state).
    Recovering,
}

// ---------------------------------------------------------------------------
// SafeModeManager — orchestrates safe-mode activation and recovery
// ---------------------------------------------------------------------------

/// Manager for deterministic safe-mode degradation and recovery.
///
/// Tracks active safe modes per failure type, manages evidence ring buffer
/// fallback, and records structured events for all transitions.
#[derive(Debug, Clone)]
pub struct SafeModeManager {
    /// Current status per failure type.
    status: BTreeMap<FailureType, SafeModeStatus>,
    /// Evidence ring buffer fallback (used when primary ledger is full).
    ring_buffer: EvidenceRingBuffer,
    /// Ring buffer capacity.
    ring_buffer_capacity: usize,
    /// Whether high-impact actions are blocked (evidence ledger full).
    high_impact_blocked: bool,
    /// Extensions refused (adapter unavailable).
    extensions_refused: bool,
    /// Quarantined extensions (decision contract errors).
    quarantined_extensions: BTreeMap<String, String>,
    /// Accumulated safe-mode events.
    events: Vec<SafeModeEvent>,
    /// Count of activations per failure type.
    activation_counts: BTreeMap<FailureType, u64>,
    /// Count of recoveries per failure type.
    recovery_counts: BTreeMap<FailureType, u64>,
}

/// Default ring buffer capacity for evidence fallback.
const DEFAULT_RING_BUFFER_CAPACITY: usize = 256;

impl Default for SafeModeManager {
    fn default() -> Self {
        Self::new(DEFAULT_RING_BUFFER_CAPACITY)
    }
}

impl SafeModeManager {
    /// Create a new manager with the specified ring buffer capacity.
    pub fn new(ring_buffer_capacity: usize) -> Self {
        Self {
            status: BTreeMap::new(),
            ring_buffer: EvidenceRingBuffer::new(ring_buffer_capacity),
            ring_buffer_capacity,
            high_impact_blocked: false,
            extensions_refused: false,
            quarantined_extensions: BTreeMap::new(),
            events: Vec::new(),
            activation_counts: BTreeMap::new(),
            recovery_counts: BTreeMap::new(),
        }
    }

    /// Current status for a given failure type.
    pub fn status(&self, failure_type: FailureType) -> SafeModeStatus {
        self.status
            .get(&failure_type)
            .copied()
            .unwrap_or(SafeModeStatus::Normal)
    }

    /// Whether any safe mode is currently active.
    pub fn any_active(&self) -> bool {
        self.status.values().any(|s| *s == SafeModeStatus::Active)
    }

    /// Whether extensions are currently refused.
    pub fn extensions_refused(&self) -> bool {
        self.extensions_refused
    }

    /// Whether high-impact actions are blocked.
    pub fn high_impact_blocked(&self) -> bool {
        self.high_impact_blocked
    }

    /// View quarantined extensions.
    pub fn quarantined_extensions(&self) -> &BTreeMap<String, String> {
        &self.quarantined_extensions
    }

    /// View the evidence ring buffer.
    pub fn ring_buffer(&self) -> &EvidenceRingBuffer {
        &self.ring_buffer
    }

    /// View accumulated events.
    pub fn events(&self) -> &[SafeModeEvent] {
        &self.events
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<SafeModeEvent> {
        std::mem::take(&mut self.events)
    }

    /// Total activation count for a failure type.
    pub fn activation_count(&self, failure_type: FailureType) -> u64 {
        self.activation_counts
            .get(&failure_type)
            .copied()
            .unwrap_or(0)
    }

    /// Total recovery count for a failure type.
    pub fn recovery_count(&self, failure_type: FailureType) -> u64 {
        self.recovery_counts
            .get(&failure_type)
            .copied()
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Failure handlers — each failure type activates its corresponding safe mode
    // -----------------------------------------------------------------------

    /// Handle adapter unavailable: refuse extensions, emit diagnostic.
    pub fn handle_adapter_unavailable(
        &mut self,
        trace_id: &str,
        diagnostic: &str,
    ) -> SafeModeAction {
        self.activate(FailureType::AdapterUnavailable, trace_id, diagnostic, None);
        self.extensions_refused = true;
        SafeModeAction::RefuseExtensions {
            diagnostic: diagnostic.to_string(),
        }
    }

    /// Handle decision contract error: default-deny and quarantine extension.
    pub fn handle_decision_contract_error(
        &mut self,
        trace_id: &str,
        extension_id: &str,
        error_code: &str,
    ) -> SafeModeAction {
        let reason = format!("decision contract error: {error_code}");
        self.activate(
            FailureType::DecisionContractError,
            trace_id,
            &reason,
            Some(error_code),
        );
        self.quarantined_extensions
            .insert(extension_id.to_string(), reason.clone());
        SafeModeAction::DefaultDenyAndQuarantine {
            extension_id: extension_id.to_string(),
            reason,
        }
    }

    /// Handle evidence ledger full: switch to ring buffer, block high-impact.
    pub fn handle_evidence_ledger_full(
        &mut self,
        trace_id: &str,
        error_code: &str,
    ) -> SafeModeAction {
        self.activate(
            FailureType::EvidenceLedgerFull,
            trace_id,
            "evidence ledger full; switching to ring buffer",
            Some(error_code),
        );
        self.high_impact_blocked = true;
        SafeModeAction::RingBufferFallback {
            capacity: self.ring_buffer_capacity,
            high_impact_blocked: true,
        }
    }

    /// Handle Cx corruption: reject current operation, prepare fresh Cx.
    pub fn handle_cx_corrupted(
        &mut self,
        trace_id: &str,
        operation: &str,
        corruption_detail: &str,
    ) -> SafeModeAction {
        self.activate(
            FailureType::CxCorrupted,
            trace_id,
            corruption_detail,
            Some("cx_corrupted"),
        );
        SafeModeAction::RejectAndRefreshCx {
            rejected_operation: operation.to_string(),
            corruption_detail: corruption_detail.to_string(),
        }
    }

    /// Handle cancellation deadlock: force-finalize after timeout.
    pub fn handle_cancellation_deadlock(
        &mut self,
        trace_id: &str,
        cell_id: &str,
        timeout_ticks: u64,
    ) -> SafeModeAction {
        let detail = format!("cancellation stuck after {timeout_ticks} ticks on cell {cell_id}");
        self.activate(
            FailureType::CancellationDeadlock,
            trace_id,
            &detail,
            Some("cancellation_deadlock"),
        );
        SafeModeAction::ForceFinalize {
            cell_id: cell_id.to_string(),
            timeout_ticks,
        }
    }

    /// Write a fallback evidence entry into the ring buffer.
    pub fn write_ring_buffer_entry(
        &mut self,
        trace_id: &str,
        event: &str,
        outcome: &str,
        component: &str,
    ) {
        let seq = self.ring_buffer.total_written();
        self.ring_buffer.push(RingBufferEntry {
            trace_id: trace_id.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            component: component.to_string(),
            sequence: seq,
        });
    }

    /// Check whether an extension is quarantined (returns deny reason if so).
    pub fn check_quarantine(&self, extension_id: &str) -> Option<&String> {
        self.quarantined_extensions.get(extension_id)
    }

    /// Check whether an action should be blocked due to safe mode.
    ///
    /// Returns `Some(reason)` if the action should be blocked, `None` if allowed.
    pub fn check_action_blocked(&self, is_high_impact: bool) -> Option<String> {
        if self.extensions_refused {
            return Some("extensions refused: adapter unavailable".to_string());
        }
        if is_high_impact && self.high_impact_blocked {
            return Some("high-impact actions blocked: evidence ledger unavailable".to_string());
        }
        None
    }

    // -----------------------------------------------------------------------
    // Recovery — resolve failure and exit safe mode
    // -----------------------------------------------------------------------

    /// Recover from adapter unavailable: re-enable extension loading.
    pub fn recover_adapter(&mut self, trace_id: &str) {
        self.extensions_refused = false;
        self.recover(FailureType::AdapterUnavailable, trace_id);
    }

    /// Recover from decision contract error: un-quarantine an extension.
    pub fn recover_decision_contract(&mut self, trace_id: &str, extension_id: &str) {
        self.quarantined_extensions.remove(extension_id);
        if self.quarantined_extensions.is_empty() {
            self.recover(FailureType::DecisionContractError, trace_id);
        }
    }

    /// Recover from evidence ledger full: drain ring buffer, unblock actions.
    pub fn recover_evidence_ledger(&mut self, trace_id: &str) -> Vec<RingBufferEntry> {
        self.high_impact_blocked = false;
        let entries = self.ring_buffer.drain();
        self.recover(FailureType::EvidenceLedgerFull, trace_id);
        entries
    }

    /// Recover from Cx corruption.
    pub fn recover_cx(&mut self, trace_id: &str) {
        self.recover(FailureType::CxCorrupted, trace_id);
    }

    /// Recover from cancellation deadlock.
    pub fn recover_cancellation(&mut self, trace_id: &str) {
        self.recover(FailureType::CancellationDeadlock, trace_id);
    }

    // -----------------------------------------------------------------------
    // Validate — check a decision against safe-mode constraints
    // -----------------------------------------------------------------------

    /// Validate a decision request against safe-mode constraints.
    ///
    /// If safe mode is active, returns `DecisionVerdict::Deny` with evidence
    /// written to the ring buffer. Otherwise delegates to the decision adapter.
    pub fn validate_decision<D: DecisionAdapter>(
        &mut self,
        adapter: &mut D,
        request: &DecisionRequest,
        extension_id: &str,
    ) -> Result<DecisionVerdict, ControlPlaneAdapterError> {
        // Check quarantine first (clone reason to release borrow)
        if let Some(reason) = self.check_quarantine(extension_id).cloned() {
            self.write_ring_buffer_entry(
                &request.trace_id.to_string(),
                "decision_denied_quarantine",
                "deny",
                "safe_mode_fallback",
            );
            self.emit_event(
                &request.trace_id.to_string(),
                FailureType::DecisionContractError,
                "validate_decision",
                &format!("quarantined: {reason}"),
                None,
            );
            return Ok(DecisionVerdict::Deny);
        }

        // Check extensions refused
        if self.extensions_refused {
            self.write_ring_buffer_entry(
                &request.trace_id.to_string(),
                "decision_denied_adapter_unavailable",
                "deny",
                "safe_mode_fallback",
            );
            return Ok(DecisionVerdict::Deny);
        }

        // Delegate to real adapter
        match adapter.evaluate(request) {
            Ok(verdict) => Ok(verdict),
            Err(err) => {
                // Decision contract failed — activate safe mode, default-deny
                let error_code = err.error_code();
                self.handle_decision_contract_error(
                    &request.trace_id.to_string(),
                    extension_id,
                    error_code,
                );
                Ok(DecisionVerdict::Deny)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn activate(
        &mut self,
        failure_type: FailureType,
        trace_id: &str,
        detail: &str,
        error_code: Option<&str>,
    ) {
        self.status.insert(failure_type, SafeModeStatus::Active);
        *self.activation_counts.entry(failure_type).or_insert(0) += 1;
        self.emit_event(trace_id, failure_type, "activate", detail, error_code);
    }

    fn recover(&mut self, failure_type: FailureType, trace_id: &str) {
        self.status.insert(failure_type, SafeModeStatus::Recovering);
        self.emit_event(trace_id, failure_type, "recover", "recovering", None);
        self.status.insert(failure_type, SafeModeStatus::Normal);
        *self.recovery_counts.entry(failure_type).or_insert(0) += 1;
        self.emit_event(trace_id, failure_type, "recover", "recovery_complete", None);
    }

    fn emit_event(
        &mut self,
        trace_id: &str,
        failure_type: FailureType,
        phase: &str,
        detail: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(SafeModeEvent {
            trace_id: trace_id.to_string(),
            failure_type,
            phase: phase.to_string(),
            action_summary: detail.to_string(),
            component: "safe_mode_fallback".to_string(),
            outcome: if phase == "activate" {
                "safe_mode_active".to_string()
            } else if phase == "recover" {
                "recovery_complete".to_string()
            } else {
                "safe_mode_active".to_string()
            },
            error_code: error_code.map(|s| s.to_string()),
        });
    }
}

// ---------------------------------------------------------------------------
// Attestation-aware fallback policy (bd-1gcu)
// ---------------------------------------------------------------------------

const ATTESTATION_COMPONENT: &str = "attestation_safe_mode";
const ATTESTATION_PENDING_STATUS: &str = "attestation-pending";

/// Current attestation-health input to fallback evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AttestationHealth {
    /// Attestation checks are valid and fresh.
    Valid,
    /// Attestation checks failed cryptographic/policy validation.
    VerificationFailed,
    /// Attestation evidence exists but is stale/expired.
    EvidenceExpired,
    /// Attestation evidence is unavailable (missing cache/source/outage).
    EvidenceUnavailable,
}

impl AttestationHealth {
    /// Whether this health state is usable for high-impact autonomy.
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Valid)
    }

    fn status_label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::VerificationFailed => "verification_failed",
            Self::EvidenceExpired => "expired",
            Self::EvidenceUnavailable => "unavailable",
        }
    }

    fn error_code(self) -> Option<&'static str> {
        match self {
            Self::Valid => None,
            Self::VerificationFailed => Some("attestation_verification_failed"),
            Self::EvidenceExpired => Some("attestation_expired"),
            Self::EvidenceUnavailable => Some("attestation_unavailable"),
        }
    }
}

impl fmt::Display for AttestationHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.status_label())
    }
}

/// Operational impact tier for autonomous actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActionTier {
    HighImpact,
    Standard,
    LowImpact,
}

impl fmt::Display for ActionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HighImpact => f.write_str("high_impact"),
            Self::Standard => f.write_str("standard"),
            Self::LowImpact => f.write_str("low_impact"),
        }
    }
}

/// Deterministic action taxonomy used by attestation fallback policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AutonomousAction {
    /// High-impact: isolate subject aggressively.
    Quarantine,
    /// High-impact: terminate subject execution.
    Terminate,
    /// High-impact: emergency capability grant.
    EmergencyGrant,
    /// High-impact: policy promotion/change.
    PolicyPromotion,
    /// High-impact: capability escalation.
    CapabilityEscalation,
    /// Standard: routine monitoring.
    RoutineMonitoring,
    /// Standard: evidence collection path.
    EvidenceCollection,
    /// Low-impact: telemetry/metrics only.
    MetricsEmission,
}

impl AutonomousAction {
    /// Default impact tier for this action class.
    pub fn default_tier(self) -> ActionTier {
        match self {
            Self::Quarantine
            | Self::Terminate
            | Self::EmergencyGrant
            | Self::PolicyPromotion
            | Self::CapabilityEscalation => ActionTier::HighImpact,
            Self::RoutineMonitoring | Self::EvidenceCollection => ActionTier::Standard,
            Self::MetricsEmission => ActionTier::LowImpact,
        }
    }

    fn action_name(self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::Terminate => "terminate",
            Self::EmergencyGrant => "emergency_grant",
            Self::PolicyPromotion => "policy_promotion",
            Self::CapabilityEscalation => "capability_escalation",
            Self::RoutineMonitoring => "routine_monitoring",
            Self::EvidenceCollection => "evidence_collection",
            Self::MetricsEmission => "metrics_emission",
        }
    }
}

impl fmt::Display for AutonomousAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.action_name())
    }
}

/// Request envelope evaluated by attestation fallback policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationActionRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action: AutonomousAction,
    pub tier: ActionTier,
    pub timestamp_ns: u64,
}

impl AttestationActionRequest {
    /// Construct a request using action-default tiering.
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        action: AutonomousAction,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            action,
            tier: action.default_tier(),
            timestamp_ns,
        }
    }
}

/// State machine for attestation-driven autonomy fallback.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum AttestationFallbackState {
    /// Normal autonomous operation.
    #[default]
    Normal,
    /// Degraded challenge/sandbox-first operation.
    Degraded,
    /// Temporary state while moving queued backlog for validation.
    Restoring,
}

impl fmt::Display for AttestationFallbackState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normal => f.write_str("normal"),
            Self::Degraded => f.write_str("degraded"),
            Self::Restoring => f.write_str("restoring"),
        }
    }
}

/// Configurable fallback policy knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationFallbackConfig {
    /// Timeout for persistent unavailability before mandatory operator review.
    pub unavailable_timeout_ns: u64,
    /// Whether challenge is required for deferred high-impact actions.
    pub challenge_on_fallback: bool,
    /// Whether sandbox is required for deferred high-impact actions.
    pub sandbox_on_fallback: bool,
}

impl Default for AttestationFallbackConfig {
    fn default() -> Self {
        Self {
            unavailable_timeout_ns: 300_000_000_000, // 5 minutes
            challenge_on_fallback: true,
            sandbox_on_fallback: true,
        }
    }
}

/// Queued high-impact decision awaiting attestation restoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedAttestationDecision {
    pub queue_id: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action: AutonomousAction,
    pub queued_at_ns: u64,
    /// Always `attestation-pending`.
    pub status: String,
}

/// Fallback outcome for one action evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationFallbackDecision {
    /// Action can proceed (optionally with warning for non-high-impact tiers).
    Execute {
        attestation_status: String,
        warning: Option<String>,
    },
    /// Action deferred under degraded mode with explicit pending status.
    Deferred {
        queue_id: u64,
        attestation_status: String,
        status: String,
        challenge_required: bool,
        sandbox_required: bool,
    },
}

/// Stable structured event envelope for attestation fallback policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationFallbackEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub detail: String,
}

/// Signed transition receipt for fallback activation/deactivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationTransitionReceipt {
    pub sequence: u64,
    pub from_state: AttestationFallbackState,
    pub to_state: AttestationFallbackState,
    pub reason: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub timestamp_ns: u64,
    pub signer_verification_key: VerificationKey,
    pub signature: Signature,
}

impl AttestationTransitionReceipt {
    fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(self.from_state.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.to_state.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.reason.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.trace_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.decision_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.policy_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        buf.extend_from_slice(self.signer_verification_key.as_bytes());
        buf.extend_from_slice(&SIGNATURE_SENTINEL);
        buf
    }

    fn signed(
        sequence: u64,
        from_state: AttestationFallbackState,
        to_state: AttestationFallbackState,
        reason: &str,
        request: &AttestationActionRequest,
        signing_key: &SigningKey,
    ) -> Result<Self, SignatureError> {
        let mut receipt = Self {
            sequence,
            from_state,
            to_state,
            reason: reason.to_string(),
            trace_id: request.trace_id.clone(),
            decision_id: request.decision_id.clone(),
            policy_id: request.policy_id.clone(),
            timestamp_ns: request.timestamp_ns,
            signer_verification_key: signing_key.verification_key(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        receipt.signature = sign_preimage(signing_key, &receipt.preimage())?;
        Ok(receipt)
    }

    /// Verify transition receipt signature.
    pub fn verify(&self) -> Result<(), SignatureError> {
        verify_signature(
            &self.signer_verification_key,
            &self.preimage(),
            &self.signature,
        )
    }
}

/// Errors from attestation fallback policy management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationFallbackError {
    SignatureFailure { detail: String },
}

impl fmt::Display for AttestationFallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureFailure { detail } => {
                write!(f, "transition receipt signature failure: {detail}")
            }
        }
    }
}

impl std::error::Error for AttestationFallbackError {}

impl From<SignatureError> for AttestationFallbackError {
    fn from(value: SignatureError) -> Self {
        Self::SignatureFailure {
            detail: value.to_string(),
        }
    }
}

/// Deterministic policy manager for attestation-driven fallback behavior.
#[derive(Debug, Clone)]
pub struct AttestationFallbackManager {
    config: AttestationFallbackConfig,
    state: AttestationFallbackState,
    health: AttestationHealth,
    degraded_since_ns: Option<u64>,
    operator_review_required: bool,
    queue_seq: u64,
    transition_seq: u64,
    pending_decisions: Vec<QueuedAttestationDecision>,
    recovery_backlog: Vec<QueuedAttestationDecision>,
    transition_receipts: Vec<AttestationTransitionReceipt>,
    events: Vec<AttestationFallbackEvent>,
    transition_signing_key: SigningKey,
}

impl AttestationFallbackManager {
    /// Create a manager with explicit transition-signing key.
    pub fn new(config: AttestationFallbackConfig, transition_signing_key: SigningKey) -> Self {
        Self {
            config,
            state: AttestationFallbackState::Normal,
            health: AttestationHealth::Valid,
            degraded_since_ns: None,
            operator_review_required: false,
            queue_seq: 0,
            transition_seq: 0,
            pending_decisions: Vec::new(),
            recovery_backlog: Vec::new(),
            transition_receipts: Vec::new(),
            events: Vec::new(),
            transition_signing_key,
        }
    }

    /// Create a manager with deterministic default signing key.
    pub fn with_default_signing_key(config: AttestationFallbackConfig) -> Self {
        Self::new(config, SigningKey::from_bytes([11u8; 32]))
    }

    /// Current fallback state.
    pub fn state(&self) -> AttestationFallbackState {
        self.state
    }

    /// Current observed health.
    pub fn health(&self) -> AttestationHealth {
        self.health
    }

    /// Whether operator-mandatory review is currently required.
    pub fn operator_review_required(&self) -> bool {
        self.operator_review_required
    }

    /// Read-only view of pending high-impact decisions.
    pub fn pending_decisions(&self) -> &[QueuedAttestationDecision] {
        &self.pending_decisions
    }

    /// Read-only view of signed transition receipts.
    pub fn transition_receipts(&self) -> &[AttestationTransitionReceipt] {
        &self.transition_receipts
    }

    /// Read-only view of emitted structured events.
    pub fn events(&self) -> &[AttestationFallbackEvent] {
        &self.events
    }

    /// Drain queued decisions that were moved during restoration.
    pub fn take_recovery_backlog(&mut self) -> Vec<QueuedAttestationDecision> {
        std::mem::take(&mut self.recovery_backlog)
    }

    /// Evaluate one action under current attestation health.
    pub fn evaluate_action(
        &mut self,
        request: AttestationActionRequest,
        health: AttestationHealth,
    ) -> Result<AttestationFallbackDecision, AttestationFallbackError> {
        self.update_health_state(&request, health)?;

        match request.tier {
            ActionTier::LowImpact => {
                self.emit_event(
                    &request,
                    "attestation_low_impact_allowed",
                    "pass",
                    None,
                    "low-impact action does not require attestation",
                );
                Ok(AttestationFallbackDecision::Execute {
                    attestation_status: self.health.status_label().to_string(),
                    warning: None,
                })
            }
            ActionTier::Standard => {
                if self.health.is_healthy() {
                    self.emit_event(
                        &request,
                        "attestation_standard_allowed",
                        "pass",
                        None,
                        "standard action allowed with healthy attestation",
                    );
                    Ok(AttestationFallbackDecision::Execute {
                        attestation_status: "valid".to_string(),
                        warning: None,
                    })
                } else {
                    let warning = format!(
                        "attestation {} for standard action {}; continuing with warning",
                        self.health, request.action
                    );
                    self.emit_event(
                        &request,
                        "attestation_standard_warn",
                        "warn",
                        self.health.error_code(),
                        &warning,
                    );
                    Ok(AttestationFallbackDecision::Execute {
                        attestation_status: "degraded".to_string(),
                        warning: Some(warning),
                    })
                }
            }
            ActionTier::HighImpact => {
                if self.health.is_healthy() && self.state == AttestationFallbackState::Normal {
                    self.emit_event(
                        &request,
                        "attestation_high_impact_allowed",
                        "pass",
                        None,
                        "high-impact action allowed with healthy attestation",
                    );
                    return Ok(AttestationFallbackDecision::Execute {
                        attestation_status: "valid".to_string(),
                        warning: None,
                    });
                }

                let queue_id = self.queue_seq;
                self.queue_seq = self.queue_seq.saturating_add(1);
                self.pending_decisions.push(QueuedAttestationDecision {
                    queue_id,
                    trace_id: request.trace_id.clone(),
                    decision_id: request.decision_id.clone(),
                    policy_id: request.policy_id.clone(),
                    action: request.action,
                    queued_at_ns: request.timestamp_ns,
                    status: ATTESTATION_PENDING_STATUS.to_string(),
                });

                let detail = format!(
                    "high-impact action {} deferred with status {} under {} attestation",
                    request.action, ATTESTATION_PENDING_STATUS, self.health
                );
                self.emit_event(
                    &request,
                    "attestation_high_impact_deferred",
                    "defer",
                    self.health.error_code(),
                    &detail,
                );
                Ok(AttestationFallbackDecision::Deferred {
                    queue_id,
                    attestation_status: "degraded".to_string(),
                    status: ATTESTATION_PENDING_STATUS.to_string(),
                    challenge_required: self.config.challenge_on_fallback,
                    sandbox_required: self.config.sandbox_on_fallback,
                })
            }
        }
    }

    fn update_health_state(
        &mut self,
        request: &AttestationActionRequest,
        health: AttestationHealth,
    ) -> Result<(), AttestationFallbackError> {
        self.health = health;

        if health.is_healthy() {
            if self.state == AttestationFallbackState::Degraded {
                self.transition_state(
                    request,
                    AttestationFallbackState::Restoring,
                    "attestation_restored",
                )?;
                // Transition to Normal BEFORE moving pending_decisions so that
                // on failure the pending_decisions buffer remains intact.
                self.transition_state(
                    request,
                    AttestationFallbackState::Normal,
                    "attestation_recovery_complete",
                )?;
                self.recovery_backlog = std::mem::take(&mut self.pending_decisions);
                self.degraded_since_ns = None;
                self.operator_review_required = false;
                self.emit_event(
                    request,
                    "attestation_recovery_backlog_ready",
                    "pass",
                    None,
                    format!(
                        "recovery backlog moved for validation: {} queued decisions",
                        self.recovery_backlog.len()
                    ),
                );
            }
            return Ok(());
        }

        if self.state != AttestationFallbackState::Degraded {
            self.transition_state(
                request,
                AttestationFallbackState::Degraded,
                "attestation_degraded",
            )?;
            self.degraded_since_ns = Some(request.timestamp_ns);
        } else if self.degraded_since_ns.is_none() {
            self.degraded_since_ns = Some(request.timestamp_ns);
        }

        if health == AttestationHealth::EvidenceUnavailable {
            self.maybe_escalate_operator_review(request);
        }

        Ok(())
    }

    fn maybe_escalate_operator_review(&mut self, request: &AttestationActionRequest) {
        let Some(degraded_since_ns) = self.degraded_since_ns else {
            return;
        };
        if self.operator_review_required {
            return;
        }
        let elapsed = request.timestamp_ns.saturating_sub(degraded_since_ns);
        if elapsed >= self.config.unavailable_timeout_ns {
            self.operator_review_required = true;
            self.emit_event(
                request,
                "attestation_operator_review_required",
                "fail",
                Some("attestation_unavailable_timeout"),
                format!(
                    "attestation unavailable for {}ns (threshold {}ns)",
                    elapsed, self.config.unavailable_timeout_ns
                ),
            );
        }
    }

    fn transition_state(
        &mut self,
        request: &AttestationActionRequest,
        to_state: AttestationFallbackState,
        reason: &str,
    ) -> Result<(), AttestationFallbackError> {
        let from_state = self.state;
        if from_state == to_state {
            return Ok(());
        }
        let receipt = AttestationTransitionReceipt::signed(
            self.transition_seq,
            from_state,
            to_state,
            reason,
            request,
            &self.transition_signing_key,
        )?;
        self.transition_seq = self.transition_seq.saturating_add(1);
        self.state = to_state;
        self.transition_receipts.push(receipt);

        self.emit_event(
            request,
            "attestation_state_transition",
            "pass",
            None,
            format!("{from_state} -> {to_state} ({reason})"),
        );
        Ok(())
    }

    fn emit_event(
        &mut self,
        request: &AttestationActionRequest,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
        detail: impl Into<String>,
    ) {
        self.events.push(AttestationFallbackEvent {
            trace_id: request.trace_id.clone(),
            decision_id: request.decision_id.clone(),
            policy_id: request.policy_id.clone(),
            component: ATTESTATION_COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(std::string::ToString::to_string),
            detail: detail.into(),
        });
    }
}

/// Map unified verifier output to attestation-health input for fallback policy.
pub fn attestation_health_from_verdict(
    verdict: &UnifiedReceiptVerificationVerdict,
) -> AttestationHealth {
    if verdict.attestation.passed
        && verdict.failure_class != Some(VerificationFailureClass::StaleData)
        && !verdict
            .warnings
            .iter()
            .any(|w| w.starts_with("attestation_"))
    {
        return AttestationHealth::Valid;
    }

    if matches!(
        verdict.attestation.error_code.as_deref(),
        Some("attestation_policy_quote_age_mismatch")
    ) || verdict
        .warnings
        .iter()
        .any(|warning| warning.starts_with("attestation_") && warning.contains("stale"))
    {
        return AttestationHealth::EvidenceExpired;
    }

    if matches!(
        verdict.attestation.error_code.as_deref(),
        Some("attestation_trust_root_missing")
            | Some("attestation_quote_digest_unavailable")
            | Some("attestation_measurement_id_derivation_failed")
    ) {
        return AttestationHealth::EvidenceUnavailable;
    }

    if verdict.failure_class == Some(VerificationFailureClass::StaleData) {
        return AttestationHealth::EvidenceExpired;
    }

    AttestationHealth::VerificationFailed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{
        MockBudget, MockCx, MockDecisionContract, MockFailureMode, trace_id_from_seed,
    };
    use crate::control_plane::mocks::{decision_id_from_seed, policy_id_from_seed};
    use crate::control_plane::{DecisionRequest, DecisionVerdict};

    #[allow(dead_code)]
    fn mock_cx(seed: u64) -> MockCx {
        MockCx::new(trace_id_from_seed(seed), MockBudget::new(100_000))
    }

    fn mock_request(seed: u64) -> DecisionRequest {
        DecisionRequest {
            decision_id: decision_id_from_seed(seed),
            policy_id: policy_id_from_seed(seed),
            trace_id: trace_id_from_seed(seed),
            ts_unix_ms: 1_700_000_000_000 + seed,
            calibration_score_bps: 8000,
            e_process_milli: 50,
            ci_width_milli: 100,
        }
    }

    // -- FailureType tests --

    #[test]
    fn failure_type_display() {
        assert_eq!(
            FailureType::AdapterUnavailable.to_string(),
            "adapter_unavailable"
        );
        assert_eq!(
            FailureType::DecisionContractError.to_string(),
            "decision_contract_error"
        );
        assert_eq!(
            FailureType::EvidenceLedgerFull.to_string(),
            "evidence_ledger_full"
        );
        assert_eq!(FailureType::CxCorrupted.to_string(), "cx_corrupted");
        assert_eq!(
            FailureType::CancellationDeadlock.to_string(),
            "cancellation_deadlock"
        );
    }

    #[test]
    fn failure_type_ordering() {
        assert!(FailureType::AdapterUnavailable < FailureType::DecisionContractError);
        assert!(FailureType::DecisionContractError < FailureType::EvidenceLedgerFull);
        assert!(FailureType::EvidenceLedgerFull < FailureType::CxCorrupted);
        assert!(FailureType::CxCorrupted < FailureType::CancellationDeadlock);
    }

    #[test]
    fn failure_type_serde_roundtrip() {
        for ft in [
            FailureType::AdapterUnavailable,
            FailureType::DecisionContractError,
            FailureType::EvidenceLedgerFull,
            FailureType::CxCorrupted,
            FailureType::CancellationDeadlock,
        ] {
            let json = serde_json::to_string(&ft).unwrap();
            let parsed: FailureType = serde_json::from_str(&json).unwrap();
            assert_eq!(ft, parsed);
        }
    }

    // -- SafeModeAction tests --

    #[test]
    fn safe_mode_action_failure_type_mapping() {
        let action = SafeModeAction::RefuseExtensions {
            diagnostic: "test".to_string(),
        };
        assert_eq!(action.failure_type(), FailureType::AdapterUnavailable);

        let action = SafeModeAction::DefaultDenyAndQuarantine {
            extension_id: "ext1".to_string(),
            reason: "err".to_string(),
        };
        assert_eq!(action.failure_type(), FailureType::DecisionContractError);

        let action = SafeModeAction::RingBufferFallback {
            capacity: 128,
            high_impact_blocked: true,
        };
        assert_eq!(action.failure_type(), FailureType::EvidenceLedgerFull);

        let action = SafeModeAction::RejectAndRefreshCx {
            rejected_operation: "op".to_string(),
            corruption_detail: "bad".to_string(),
        };
        assert_eq!(action.failure_type(), FailureType::CxCorrupted);

        let action = SafeModeAction::ForceFinalize {
            cell_id: "c1".to_string(),
            timeout_ticks: 100,
        };
        assert_eq!(action.failure_type(), FailureType::CancellationDeadlock);
    }

    #[test]
    fn safe_mode_action_serde_roundtrip() {
        let actions = vec![
            SafeModeAction::RefuseExtensions {
                diagnostic: "version mismatch".to_string(),
            },
            SafeModeAction::DefaultDenyAndQuarantine {
                extension_id: "ext-abc".to_string(),
                reason: "contract panic".to_string(),
            },
            SafeModeAction::RingBufferFallback {
                capacity: 256,
                high_impact_blocked: true,
            },
            SafeModeAction::RejectAndRefreshCx {
                rejected_operation: "hostcall_read".to_string(),
                corruption_detail: "budget underflow".to_string(),
            },
            SafeModeAction::ForceFinalize {
                cell_id: "cell-42".to_string(),
                timeout_ticks: 5000,
            },
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: SafeModeAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, parsed);
        }
    }

    // -- SafeModeEvent tests --

    #[test]
    fn safe_mode_event_serde_roundtrip() {
        let event = SafeModeEvent {
            trace_id: "t1".to_string(),
            failure_type: FailureType::CxCorrupted,
            phase: "activate".to_string(),
            action_summary: "budget underflow".to_string(),
            component: "safe_mode_fallback".to_string(),
            outcome: "safe_mode_active".to_string(),
            error_code: Some("cx_corrupted".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: SafeModeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -- EvidenceRingBuffer tests --

    #[test]
    fn ring_buffer_basic_push_and_read() {
        let mut rb = EvidenceRingBuffer::new(3);
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
        assert_eq!(rb.total_written(), 0);

        rb.push(RingBufferEntry {
            trace_id: "t1".to_string(),
            event: "e1".to_string(),
            outcome: "ok".to_string(),
            component: "c".to_string(),
            sequence: 0,
        });
        assert_eq!(rb.len(), 1);
        assert_eq!(rb.total_written(), 1);
        assert_eq!(rb.entries()[0].trace_id, "t1");
    }

    #[test]
    fn ring_buffer_overflow_wraps() {
        let mut rb = EvidenceRingBuffer::new(2);
        for i in 0..5 {
            rb.push(RingBufferEntry {
                trace_id: format!("t{i}"),
                event: "e".to_string(),
                outcome: "ok".to_string(),
                component: "c".to_string(),
                sequence: i,
            });
        }
        assert_eq!(rb.len(), 2);
        assert_eq!(rb.total_written(), 5);
        // Should have the two most recent entries in order
        let entries = rb.entries();
        assert_eq!(entries[0].trace_id, "t3");
        assert_eq!(entries[1].trace_id, "t4");
    }

    #[test]
    fn ring_buffer_drain_clears() {
        let mut rb = EvidenceRingBuffer::new(4);
        for i in 0..3 {
            rb.push(RingBufferEntry {
                trace_id: format!("t{i}"),
                event: "e".to_string(),
                outcome: "ok".to_string(),
                component: "c".to_string(),
                sequence: i,
            });
        }
        let drained = rb.drain();
        assert_eq!(drained.len(), 3);
        assert!(rb.is_empty());
    }

    #[test]
    fn ring_buffer_serde_roundtrip() {
        let mut rb = EvidenceRingBuffer::new(2);
        rb.push(RingBufferEntry {
            trace_id: "t1".to_string(),
            event: "e1".to_string(),
            outcome: "ok".to_string(),
            component: "c".to_string(),
            sequence: 0,
        });
        let json = serde_json::to_string(&rb).unwrap();
        let parsed: EvidenceRingBuffer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.total_written(), 1);
    }

    // -- SafeModeManager: adapter unavailable --

    #[test]
    fn adapter_unavailable_activates_safe_mode() {
        let mut mgr = SafeModeManager::default();
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Normal
        );
        assert!(!mgr.extensions_refused());

        let action =
            mgr.handle_adapter_unavailable("trace-1", "crate version mismatch v0.2 != v0.3");
        assert!(matches!(action, SafeModeAction::RefuseExtensions { .. }));
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Active
        );
        assert!(mgr.extensions_refused());
        assert!(mgr.any_active());
        assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 1);
    }

    #[test]
    fn adapter_unavailable_blocks_all_actions() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "unavailable");
        assert!(mgr.check_action_blocked(false).is_some());
        assert!(mgr.check_action_blocked(true).is_some());
    }

    #[test]
    fn adapter_unavailable_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "unavailable");
        assert!(mgr.extensions_refused());

        mgr.recover_adapter("trace-2");
        assert!(!mgr.extensions_refused());
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Normal
        );
        assert!(!mgr.any_active());
        assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 1);
    }

    // -- SafeModeManager: decision contract error --

    #[test]
    fn decision_contract_error_quarantines_extension() {
        let mut mgr = SafeModeManager::default();
        let action = mgr.handle_decision_contract_error("trace-1", "ext-bad", "unknown_action");
        assert!(matches!(
            action,
            SafeModeAction::DefaultDenyAndQuarantine { .. }
        ));
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Active
        );
        assert!(mgr.quarantined_extensions().contains_key("ext-bad"));
    }

    #[test]
    fn quarantined_extension_is_denied() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-1", "ext-bad", "err");
        assert!(mgr.check_quarantine("ext-bad").is_some());
        assert!(mgr.check_quarantine("ext-good").is_none());
    }

    #[test]
    fn decision_contract_recovery_unquarantines() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-1", "ext-bad", "err");
        mgr.recover_decision_contract("trace-2", "ext-bad");
        assert!(mgr.quarantined_extensions().is_empty());
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Normal
        );
    }

    #[test]
    fn multiple_quarantines_need_individual_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-1", "ext-a", "err1");
        mgr.handle_decision_contract_error("trace-2", "ext-b", "err2");
        assert_eq!(mgr.quarantined_extensions().len(), 2);

        mgr.recover_decision_contract("trace-3", "ext-a");
        // Still active because ext-b is still quarantined
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Active
        );

        mgr.recover_decision_contract("trace-4", "ext-b");
        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Normal
        );
    }

    // -- SafeModeManager: evidence ledger full --

    #[test]
    fn evidence_ledger_full_activates_ring_buffer() {
        let mut mgr = SafeModeManager::new(64);
        let action = mgr.handle_evidence_ledger_full("trace-1", "ledger_capacity_exceeded");
        assert!(matches!(
            action,
            SafeModeAction::RingBufferFallback {
                capacity: 64,
                high_impact_blocked: true
            }
        ));
        assert!(mgr.high_impact_blocked());
        assert_eq!(
            mgr.status(FailureType::EvidenceLedgerFull),
            SafeModeStatus::Active
        );
    }

    #[test]
    fn evidence_ledger_full_blocks_high_impact_only() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("trace-1", "full");
        assert!(mgr.check_action_blocked(true).is_some());
        // Non-high-impact actions are still allowed
        assert!(mgr.check_action_blocked(false).is_none());
    }

    #[test]
    fn evidence_fallback_writes_to_ring_buffer() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("trace-1", "full");
        mgr.write_ring_buffer_entry("trace-1", "test_event", "ok", "test_component");
        assert_eq!(mgr.ring_buffer().len(), 1);
    }

    #[test]
    fn evidence_ledger_recovery_drains_ring_buffer() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("trace-1", "full");
        mgr.write_ring_buffer_entry("trace-1", "ev1", "ok", "comp");
        mgr.write_ring_buffer_entry("trace-2", "ev2", "ok", "comp");

        let drained = mgr.recover_evidence_ledger("trace-3");
        assert_eq!(drained.len(), 2);
        assert!(!mgr.high_impact_blocked());
        assert_eq!(
            mgr.status(FailureType::EvidenceLedgerFull),
            SafeModeStatus::Normal
        );
        assert!(mgr.ring_buffer().is_empty());
    }

    // -- SafeModeManager: Cx corrupted --

    #[test]
    fn cx_corrupted_rejects_operation() {
        let mut mgr = SafeModeManager::default();
        let action =
            mgr.handle_cx_corrupted("trace-1", "hostcall_write", "budget underflow: -42ms");
        assert!(matches!(action, SafeModeAction::RejectAndRefreshCx { .. }));
        if let SafeModeAction::RejectAndRefreshCx {
            rejected_operation,
            corruption_detail,
        } = action
        {
            assert_eq!(rejected_operation, "hostcall_write");
            assert_eq!(corruption_detail, "budget underflow: -42ms");
        }
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
    }

    #[test]
    fn cx_corrupted_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("trace-1", "op", "bad budget");
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);

        mgr.recover_cx("trace-2");
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Normal);
    }

    // -- SafeModeManager: cancellation deadlock --

    #[test]
    fn cancellation_deadlock_force_finalizes() {
        let mut mgr = SafeModeManager::default();
        let action = mgr.handle_cancellation_deadlock("trace-1", "cell-42", 10_000);
        assert!(matches!(action, SafeModeAction::ForceFinalize { .. }));
        if let SafeModeAction::ForceFinalize {
            cell_id,
            timeout_ticks,
        } = action
        {
            assert_eq!(cell_id, "cell-42");
            assert_eq!(timeout_ticks, 10_000);
        }
        assert_eq!(
            mgr.status(FailureType::CancellationDeadlock),
            SafeModeStatus::Active
        );
    }

    #[test]
    fn cancellation_deadlock_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cancellation_deadlock("trace-1", "cell-42", 10_000);
        mgr.recover_cancellation("trace-2");
        assert_eq!(
            mgr.status(FailureType::CancellationDeadlock),
            SafeModeStatus::Normal
        );
    }

    // -- SafeModeManager: validate_decision integration --

    #[test]
    fn validate_decision_allows_when_normal() {
        let mut mgr = SafeModeManager::default();
        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-good")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Allow);
    }

    #[test]
    fn validate_decision_denies_quarantined_extension() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("trace-0", "ext-bad", "err");

        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-bad")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Deny);
    }

    #[test]
    fn validate_decision_denies_when_adapter_unavailable() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-0", "gone");

        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-good")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Deny);
    }

    #[test]
    fn validate_decision_auto_quarantines_on_adapter_error() {
        let mut mgr = SafeModeManager::default();
        let mut adapter =
            MockDecisionContract::new(vec![]).with_failure_mode(MockFailureMode::FailAlways {
                code: "gateway_down",
            });
        let request = mock_request(1);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-flaky")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Deny);
        assert!(mgr.quarantined_extensions().contains_key("ext-flaky"));
    }

    // -- SafeModeManager: event tracking --

    #[test]
    fn events_emitted_for_activation_and_recovery() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "gone");
        mgr.recover_adapter("trace-2");

        let events = mgr.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].phase, "activate");
        assert_eq!(events[0].failure_type, FailureType::AdapterUnavailable);
        assert_eq!(events[0].outcome, "safe_mode_active");
        assert_eq!(events[1].phase, "recover");
        assert_eq!(events[1].outcome, "recovery_complete");
        assert_eq!(events[2].phase, "recover");
        assert_eq!(events[2].outcome, "recovery_complete");
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("trace-1", "op", "bad");
        assert_eq!(mgr.events().len(), 1);
        let drained = mgr.drain_events();
        assert_eq!(drained.len(), 1);
        assert!(mgr.events().is_empty());
    }

    #[test]
    fn event_component_field_is_stable() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("trace-1", "op", "bad");
        assert_eq!(mgr.events()[0].component, "safe_mode_fallback");
    }

    // -- SafeModeManager: cascading failures --

    #[test]
    fn cascading_failure_two_simultaneous() {
        let mut mgr = SafeModeManager::default();
        // Both decision contract error and evidence ledger full at the same time
        mgr.handle_decision_contract_error("trace-1", "ext-1", "panic");
        mgr.handle_evidence_ledger_full("trace-1", "full");

        assert_eq!(
            mgr.status(FailureType::DecisionContractError),
            SafeModeStatus::Active
        );
        assert_eq!(
            mgr.status(FailureType::EvidenceLedgerFull),
            SafeModeStatus::Active
        );
        assert!(mgr.any_active());
        assert!(mgr.high_impact_blocked());
        assert!(mgr.quarantined_extensions().contains_key("ext-1"));

        // Ring buffer still works even with decision contract down
        mgr.write_ring_buffer_entry("trace-1", "cascade_event", "ok", "test");
        assert_eq!(mgr.ring_buffer().len(), 1);

        // Recover one at a time
        mgr.recover_decision_contract("trace-2", "ext-1");
        assert!(mgr.any_active()); // evidence ledger still active
        let drained = mgr.recover_evidence_ledger("trace-3");
        assert!(!mgr.any_active());
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn cascading_failure_all_five() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-1", "unavailable");
        mgr.handle_decision_contract_error("trace-2", "ext-x", "err");
        mgr.handle_evidence_ledger_full("trace-3", "full");
        mgr.handle_cx_corrupted("trace-4", "op", "bad");
        mgr.handle_cancellation_deadlock("trace-5", "cell-1", 999);

        // All 5 failure types active
        for ft in [
            FailureType::AdapterUnavailable,
            FailureType::DecisionContractError,
            FailureType::EvidenceLedgerFull,
            FailureType::CxCorrupted,
            FailureType::CancellationDeadlock,
        ] {
            assert_eq!(
                mgr.status(ft),
                SafeModeStatus::Active,
                "expected {ft} active"
            );
        }
        assert_eq!(mgr.events().len(), 5);

        // Recover all
        mgr.recover_adapter("r1");
        mgr.recover_decision_contract("r2", "ext-x");
        mgr.recover_evidence_ledger("r3");
        mgr.recover_cx("r4");
        mgr.recover_cancellation("r5");
        assert!(!mgr.any_active());
        assert_eq!(mgr.events().len(), 15); // 5 activate + 5 recover (2 events each)
    }

    // -- SafeModeManager: determinism --

    #[test]
    fn deterministic_activation_100_times() {
        // Inject the same failure 100 times; verify identical safe-mode behavior.
        let mut results = Vec::new();
        for i in 0..100 {
            let mut mgr = SafeModeManager::new(16);
            let action =
                mgr.handle_adapter_unavailable(&format!("trace-{i}"), "crate version mismatch");
            results.push((
                action,
                mgr.extensions_refused(),
                mgr.status(FailureType::AdapterUnavailable),
                mgr.activation_count(FailureType::AdapterUnavailable),
            ));
        }

        // All 100 runs should produce identical results (except trace_id in action)
        for r in &results {
            assert!(matches!(r.0, SafeModeAction::RefuseExtensions { .. }));
            assert!(r.1); // extensions_refused
            assert_eq!(r.2, SafeModeStatus::Active);
            assert_eq!(r.3, 1);
        }
    }

    #[test]
    fn deterministic_decision_error_100_times() {
        let mut results = Vec::new();
        for i in 0..100 {
            let mut mgr = SafeModeManager::default();
            let action = mgr.handle_decision_contract_error(
                &format!("trace-{i}"),
                "ext-det",
                "gateway_panic",
            );
            results.push((
                action.failure_type(),
                mgr.quarantined_extensions().contains_key("ext-det"),
                mgr.status(FailureType::DecisionContractError),
            ));
        }
        for r in &results {
            assert_eq!(r.0, FailureType::DecisionContractError);
            assert!(r.1);
            assert_eq!(r.2, SafeModeStatus::Active);
        }
    }

    #[test]
    fn deterministic_cx_corruption_100_times() {
        let mut results = Vec::new();
        for i in 0..100 {
            let mut mgr = SafeModeManager::default();
            let action =
                mgr.handle_cx_corrupted(&format!("trace-{i}"), "hostcall_read", "budget underflow");
            results.push((action.failure_type(), mgr.status(FailureType::CxCorrupted)));
        }
        for r in &results {
            assert_eq!(r.0, FailureType::CxCorrupted);
            assert_eq!(r.1, SafeModeStatus::Active);
        }
    }

    #[test]
    fn deterministic_evidence_ledger_100_times() {
        for i in 0..100 {
            let mut mgr = SafeModeManager::new(8);
            mgr.handle_evidence_ledger_full(&format!("trace-{i}"), "full");
            assert!(mgr.high_impact_blocked());
            assert_eq!(
                mgr.status(FailureType::EvidenceLedgerFull),
                SafeModeStatus::Active
            );
            mgr.write_ring_buffer_entry(&format!("trace-{i}"), "ev", "ok", "c");
            assert_eq!(mgr.ring_buffer().len(), 1);
        }
    }

    #[test]
    fn deterministic_cancellation_deadlock_100_times() {
        for i in 0..100 {
            let mut mgr = SafeModeManager::default();
            let action = mgr.handle_cancellation_deadlock(&format!("trace-{i}"), "cell-99", 5000);
            assert_eq!(action.failure_type(), FailureType::CancellationDeadlock);
            assert_eq!(
                mgr.status(FailureType::CancellationDeadlock),
                SafeModeStatus::Active
            );
        }
    }

    // -- SafeModeManager: recovery round-trip --

    #[test]
    fn full_lifecycle_activate_recover_reactivate() {
        let mut mgr = SafeModeManager::default();

        // First activation
        mgr.handle_adapter_unavailable("t1", "down");
        assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 1);

        // Recovery
        mgr.recover_adapter("t2");
        assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 1);

        // Second activation
        mgr.handle_adapter_unavailable("t3", "down again");
        assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 2);
        assert!(mgr.extensions_refused());

        // Second recovery
        mgr.recover_adapter("t4");
        assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 2);
        assert!(!mgr.extensions_refused());
    }

    // -- SafeModeStatus tests --

    #[test]
    fn safe_mode_status_default_is_normal() {
        assert_eq!(SafeModeStatus::default(), SafeModeStatus::Normal);
    }

    #[test]
    fn safe_mode_status_serde_roundtrip() {
        for status in [
            SafeModeStatus::Normal,
            SafeModeStatus::Active,
            SafeModeStatus::Recovering,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: SafeModeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    // -- RingBufferEntry tests --

    #[test]
    fn ring_buffer_entry_serde_roundtrip() {
        let entry = RingBufferEntry {
            trace_id: "t1".to_string(),
            event: "safe_mode_activated".to_string(),
            outcome: "ok".to_string(),
            component: "safe_mode_fallback".to_string(),
            sequence: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RingBufferEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    // -- Manager default configuration --

    #[test]
    fn default_manager_starts_normal() {
        let mgr = SafeModeManager::default();
        assert!(!mgr.any_active());
        assert!(!mgr.extensions_refused());
        assert!(!mgr.high_impact_blocked());
        assert!(mgr.quarantined_extensions().is_empty());
        assert!(mgr.events().is_empty());
        assert!(mgr.ring_buffer().is_empty());
    }

    #[test]
    fn custom_ring_buffer_capacity() {
        let mgr = SafeModeManager::new(32);
        assert_eq!(mgr.ring_buffer_capacity, 32);
    }

    // -- check_action_blocked edge cases --

    #[test]
    fn normal_mode_allows_all_actions() {
        let mgr = SafeModeManager::default();
        assert!(mgr.check_action_blocked(false).is_none());
        assert!(mgr.check_action_blocked(true).is_none());
    }

    #[test]
    fn adapter_unavailable_takes_precedence_over_evidence_block() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_evidence_ledger_full("t1", "full");
        mgr.handle_adapter_unavailable("t2", "gone");
        // Adapter unavailable blocks everything, not just high-impact
        let reason = mgr.check_action_blocked(false).unwrap();
        assert!(reason.contains("adapter unavailable"));
    }

    // -- Idempotent handling --

    #[test]
    fn repeated_same_failure_increments_count() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_cx_corrupted("t1", "op1", "bad1");
        mgr.handle_cx_corrupted("t2", "op2", "bad2");
        mgr.handle_cx_corrupted("t3", "op3", "bad3");
        assert_eq!(mgr.activation_count(FailureType::CxCorrupted), 3);
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
        assert_eq!(mgr.events().len(), 3);
    }

    // -- Enrichment tests --

    #[test]
    fn cascading_recovery_partial_leaves_remaining_active() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("t1", "gone");
        mgr.handle_cx_corrupted("t2", "op", "bad");
        mgr.handle_cancellation_deadlock("t3", "cell-1", 100);

        // Recover adapter only
        mgr.recover_adapter("t4");
        assert!(mgr.any_active());
        assert_eq!(
            mgr.status(FailureType::AdapterUnavailable),
            SafeModeStatus::Normal
        );
        assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
        assert_eq!(
            mgr.status(FailureType::CancellationDeadlock),
            SafeModeStatus::Active
        );

        // Recover cx
        mgr.recover_cx("t5");
        assert!(mgr.any_active());

        // Recover cancellation
        mgr.recover_cancellation("t6");
        assert!(!mgr.any_active());
    }

    #[test]
    fn ring_buffer_wrapping_under_evidence_safe_mode() {
        let mut mgr = SafeModeManager::new(3);
        mgr.handle_evidence_ledger_full("t1", "full");

        // Write 5 entries to a capacity-3 ring buffer
        for i in 0..5 {
            mgr.write_ring_buffer_entry(&format!("t-{i}"), &format!("ev-{i}"), "ok", "comp");
        }
        assert_eq!(mgr.ring_buffer().len(), 3);
        assert_eq!(mgr.ring_buffer().total_written(), 5);

        // Oldest entries should be the 3 most recent (2, 3, 4)
        let entries = mgr.ring_buffer().entries();
        assert_eq!(entries[0].trace_id, "t-2");
        assert_eq!(entries[1].trace_id, "t-3");
        assert_eq!(entries[2].trace_id, "t-4");

        // Recovery drains the 3 surviving entries
        let drained = mgr.recover_evidence_ledger("t-recover");
        assert_eq!(drained.len(), 3);
        assert!(mgr.ring_buffer().is_empty());
    }

    #[test]
    fn validate_decision_auto_quarantines_after_n_successes() {
        let mut mgr = SafeModeManager::default();
        let mut adapter =
            MockDecisionContract::new(vec![DecisionVerdict::Allow, DecisionVerdict::Allow])
                .with_failure_mode(MockFailureMode::FailAfterN {
                    remaining_successes: 2,
                    code: "gateway_crash",
                });

        // First two calls succeed
        let v1 = mgr
            .validate_decision(&mut adapter, &mock_request(1), "ext-1")
            .unwrap();
        assert_eq!(v1, DecisionVerdict::Allow);
        let v2 = mgr
            .validate_decision(&mut adapter, &mock_request(2), "ext-1")
            .unwrap();
        assert_eq!(v2, DecisionVerdict::Allow);

        // Third call fails → auto-quarantine
        let v3 = mgr
            .validate_decision(&mut adapter, &mock_request(3), "ext-1")
            .unwrap();
        assert_eq!(v3, DecisionVerdict::Deny);
        assert!(mgr.quarantined_extensions().contains_key("ext-1"));
    }

    #[test]
    fn safe_mode_events_trace_id_preserved() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_adapter_unavailable("trace-alpha", "version mismatch");
        mgr.handle_cx_corrupted("trace-beta", "write", "budget underflow");

        let events = mgr.events();
        assert_eq!(events[0].trace_id, "trace-alpha");
        assert_eq!(events[1].trace_id, "trace-beta");
    }

    #[test]
    fn recovery_count_independent_of_activation_count() {
        let mut mgr = SafeModeManager::default();
        // Activate 3 times (repeated activations without recovery between)
        mgr.handle_cx_corrupted("t1", "op1", "bad1");
        mgr.handle_cx_corrupted("t2", "op2", "bad2");
        mgr.handle_cx_corrupted("t3", "op3", "bad3");

        // Single recovery
        mgr.recover_cx("t4");
        assert_eq!(mgr.activation_count(FailureType::CxCorrupted), 3);
        assert_eq!(mgr.recovery_count(FailureType::CxCorrupted), 1);
    }

    #[test]
    fn validate_decision_good_ext_passes_when_other_quarantined() {
        let mut mgr = SafeModeManager::default();
        mgr.handle_decision_contract_error("t1", "ext-bad", "err");

        // Good extension should still be allowed if adapter works
        let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
        let request = mock_request(2);
        let verdict = mgr
            .validate_decision(&mut adapter, &request, "ext-good")
            .unwrap();
        assert_eq!(verdict, DecisionVerdict::Allow);
    }

    #[test]
    fn evidence_ring_buffer_sequence_monotonic() {
        let mut mgr = SafeModeManager::new(256);
        mgr.handle_evidence_ledger_full("t1", "full");

        for i in 0..10 {
            mgr.write_ring_buffer_entry(&format!("t-{i}"), "ev", "ok", "comp");
        }

        let entries = mgr.ring_buffer().entries();
        for window in entries.windows(2) {
            assert!(
                window[0].sequence < window[1].sequence,
                "ring buffer sequence should be monotonically increasing"
            );
        }
    }

    #[test]
    fn deterministic_cascading_all_five_100_times() {
        let mut results = Vec::new();
        for _ in 0..100 {
            let mut mgr = SafeModeManager::default();
            mgr.handle_adapter_unavailable("t1", "gone");
            mgr.handle_decision_contract_error("t2", "ext-x", "err");
            mgr.handle_evidence_ledger_full("t3", "full");
            mgr.handle_cx_corrupted("t4", "op", "bad");
            mgr.handle_cancellation_deadlock("t5", "cell-1", 999);

            let event_count = mgr.events().len();
            let active_count = [
                FailureType::AdapterUnavailable,
                FailureType::DecisionContractError,
                FailureType::EvidenceLedgerFull,
                FailureType::CxCorrupted,
                FailureType::CancellationDeadlock,
            ]
            .iter()
            .filter(|ft| mgr.status(**ft) == SafeModeStatus::Active)
            .count();

            results.push((event_count, active_count));
        }

        let first = &results[0];
        for r in &results[1..] {
            assert_eq!(r, first, "cascading all-five must be deterministic");
        }
    }

    // ================================================================
    // Attestation-aware fallback policy tests (bd-1gcu)
    // ================================================================

    use crate::receipt_verifier_pipeline::LayerResult;

    fn make_signing_key() -> SigningKey {
        SigningKey::from_bytes([42u8; 32])
    }

    fn attestation_request(
        action: AutonomousAction,
        timestamp_ns: u64,
    ) -> AttestationActionRequest {
        AttestationActionRequest::new("trace-a", "decision-a", "policy-a", action, timestamp_ns)
    }

    fn passing_verdict() -> UnifiedReceiptVerificationVerdict {
        UnifiedReceiptVerificationVerdict {
            receipt_id: "r-1".to_string(),
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            verification_timestamp_ns: 100,
            passed: true,
            failure_class: None,
            exit_code: 0,
            signature: LayerResult {
                passed: true,
                error_code: None,
                checks: vec![],
            },
            transparency: LayerResult {
                passed: true,
                error_code: None,
                checks: vec![],
            },
            attestation: LayerResult {
                passed: true,
                error_code: None,
                checks: vec![],
            },
            warnings: vec![],
            logs: vec![],
        }
    }

    // -- AttestationHealth --

    #[test]
    fn attestation_health_display_all_variants() {
        assert_eq!(AttestationHealth::Valid.to_string(), "valid");
        assert_eq!(
            AttestationHealth::VerificationFailed.to_string(),
            "verification_failed"
        );
        assert_eq!(AttestationHealth::EvidenceExpired.to_string(), "expired");
        assert_eq!(
            AttestationHealth::EvidenceUnavailable.to_string(),
            "unavailable"
        );
    }

    #[test]
    fn attestation_health_is_healthy() {
        assert!(AttestationHealth::Valid.is_healthy());
        assert!(!AttestationHealth::VerificationFailed.is_healthy());
        assert!(!AttestationHealth::EvidenceExpired.is_healthy());
        assert!(!AttestationHealth::EvidenceUnavailable.is_healthy());
    }

    #[test]
    fn attestation_health_error_code() {
        assert_eq!(AttestationHealth::Valid.error_code(), None);
        assert_eq!(
            AttestationHealth::VerificationFailed.error_code(),
            Some("attestation_verification_failed")
        );
        assert_eq!(
            AttestationHealth::EvidenceExpired.error_code(),
            Some("attestation_expired")
        );
        assert_eq!(
            AttestationHealth::EvidenceUnavailable.error_code(),
            Some("attestation_unavailable")
        );
    }

    #[test]
    fn attestation_health_serde_roundtrip() {
        for h in [
            AttestationHealth::Valid,
            AttestationHealth::VerificationFailed,
            AttestationHealth::EvidenceExpired,
            AttestationHealth::EvidenceUnavailable,
        ] {
            let json = serde_json::to_string(&h).unwrap();
            let parsed: AttestationHealth = serde_json::from_str(&json).unwrap();
            assert_eq!(h, parsed);
        }
    }

    // -- ActionTier --

    #[test]
    fn action_tier_display() {
        assert_eq!(ActionTier::HighImpact.to_string(), "high_impact");
        assert_eq!(ActionTier::Standard.to_string(), "standard");
        assert_eq!(ActionTier::LowImpact.to_string(), "low_impact");
    }

    #[test]
    fn action_tier_ordering() {
        assert!(ActionTier::HighImpact < ActionTier::Standard);
        assert!(ActionTier::Standard < ActionTier::LowImpact);
    }

    #[test]
    fn action_tier_serde_roundtrip() {
        for tier in [
            ActionTier::HighImpact,
            ActionTier::Standard,
            ActionTier::LowImpact,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: ActionTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    // -- AutonomousAction --

    #[test]
    fn autonomous_action_default_tiers() {
        assert_eq!(
            AutonomousAction::Quarantine.default_tier(),
            ActionTier::HighImpact
        );
        assert_eq!(
            AutonomousAction::Terminate.default_tier(),
            ActionTier::HighImpact
        );
        assert_eq!(
            AutonomousAction::EmergencyGrant.default_tier(),
            ActionTier::HighImpact
        );
        assert_eq!(
            AutonomousAction::PolicyPromotion.default_tier(),
            ActionTier::HighImpact
        );
        assert_eq!(
            AutonomousAction::CapabilityEscalation.default_tier(),
            ActionTier::HighImpact
        );
        assert_eq!(
            AutonomousAction::RoutineMonitoring.default_tier(),
            ActionTier::Standard
        );
        assert_eq!(
            AutonomousAction::EvidenceCollection.default_tier(),
            ActionTier::Standard
        );
        assert_eq!(
            AutonomousAction::MetricsEmission.default_tier(),
            ActionTier::LowImpact
        );
    }

    #[test]
    fn autonomous_action_display_all_variants() {
        assert_eq!(AutonomousAction::Quarantine.to_string(), "quarantine");
        assert_eq!(AutonomousAction::Terminate.to_string(), "terminate");
        assert_eq!(
            AutonomousAction::EmergencyGrant.to_string(),
            "emergency_grant"
        );
        assert_eq!(
            AutonomousAction::PolicyPromotion.to_string(),
            "policy_promotion"
        );
        assert_eq!(
            AutonomousAction::CapabilityEscalation.to_string(),
            "capability_escalation"
        );
        assert_eq!(
            AutonomousAction::RoutineMonitoring.to_string(),
            "routine_monitoring"
        );
        assert_eq!(
            AutonomousAction::EvidenceCollection.to_string(),
            "evidence_collection"
        );
        assert_eq!(
            AutonomousAction::MetricsEmission.to_string(),
            "metrics_emission"
        );
    }

    #[test]
    fn autonomous_action_serde_roundtrip() {
        for action in [
            AutonomousAction::Quarantine,
            AutonomousAction::Terminate,
            AutonomousAction::EmergencyGrant,
            AutonomousAction::PolicyPromotion,
            AutonomousAction::CapabilityEscalation,
            AutonomousAction::RoutineMonitoring,
            AutonomousAction::EvidenceCollection,
            AutonomousAction::MetricsEmission,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: AutonomousAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, parsed);
        }
    }

    // -- AttestationActionRequest --

    #[test]
    fn attestation_action_request_new_uses_default_tier() {
        let req = AttestationActionRequest::new(
            "trace-1",
            "decision-1",
            "policy-1",
            AutonomousAction::Quarantine,
            1000,
        );
        assert_eq!(req.tier, ActionTier::HighImpact);
        assert_eq!(req.trace_id, "trace-1");
        assert_eq!(req.decision_id, "decision-1");
        assert_eq!(req.policy_id, "policy-1");
        assert_eq!(req.timestamp_ns, 1000);

        let req2 =
            AttestationActionRequest::new("t", "d", "p", AutonomousAction::MetricsEmission, 500);
        assert_eq!(req2.tier, ActionTier::LowImpact);
    }

    #[test]
    fn attestation_action_request_serde_roundtrip() {
        let req = attestation_request(AutonomousAction::Terminate, 42);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AttestationActionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, parsed);
    }

    // -- AttestationFallbackState --

    #[test]
    fn attestation_fallback_state_default_is_normal() {
        assert_eq!(
            AttestationFallbackState::default(),
            AttestationFallbackState::Normal
        );
    }

    #[test]
    fn attestation_fallback_state_display() {
        assert_eq!(AttestationFallbackState::Normal.to_string(), "normal");
        assert_eq!(AttestationFallbackState::Degraded.to_string(), "degraded");
        assert_eq!(AttestationFallbackState::Restoring.to_string(), "restoring");
    }

    #[test]
    fn attestation_fallback_state_serde_roundtrip() {
        for state in [
            AttestationFallbackState::Normal,
            AttestationFallbackState::Degraded,
            AttestationFallbackState::Restoring,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: AttestationFallbackState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, parsed);
        }
    }

    // -- AttestationFallbackConfig --

    #[test]
    fn attestation_fallback_config_default() {
        let config = AttestationFallbackConfig::default();
        assert_eq!(config.unavailable_timeout_ns, 300_000_000_000);
        assert!(config.challenge_on_fallback);
        assert!(config.sandbox_on_fallback);
    }

    #[test]
    fn attestation_fallback_config_serde_roundtrip() {
        let config = AttestationFallbackConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AttestationFallbackConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    // -- AttestationFallbackError --

    #[test]
    fn attestation_fallback_error_display() {
        let err = AttestationFallbackError::SignatureFailure {
            detail: "bad key".to_string(),
        };
        assert!(err.to_string().contains("bad key"));
        assert!(err.to_string().contains("signature failure"));
    }

    #[test]
    fn attestation_fallback_error_from_signature_error() {
        let sig_err = SignatureError::PreimageError {
            detail: "test".to_string(),
        };
        let fallback_err: AttestationFallbackError = sig_err.into();
        assert!(matches!(
            fallback_err,
            AttestationFallbackError::SignatureFailure { .. }
        ));
    }

    // -- AttestationFallbackManager: low-impact actions --

    #[test]
    fn low_impact_always_allowed_when_healthy() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::MetricsEmission, 100);
        let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
        assert!(matches!(
            decision,
            AttestationFallbackDecision::Execute { ref attestation_status, warning: None }
            if attestation_status == "valid"
        ));
    }

    #[test]
    fn low_impact_allowed_when_unhealthy() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::MetricsEmission, 100);
        let decision = mgr
            .evaluate_action(req, AttestationHealth::VerificationFailed)
            .unwrap();
        // Low-impact: allowed regardless of health
        assert!(matches!(
            decision,
            AttestationFallbackDecision::Execute { .. }
        ));
    }

    // -- AttestationFallbackManager: standard actions --

    #[test]
    fn standard_action_healthy_passes_without_warning() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::RoutineMonitoring, 100);
        let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
        assert!(matches!(
            decision,
            AttestationFallbackDecision::Execute { ref attestation_status, warning: None }
            if attestation_status == "valid"
        ));
    }

    #[test]
    fn standard_action_unhealthy_executes_with_warning() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::EvidenceCollection, 100);
        let decision = mgr
            .evaluate_action(req, AttestationHealth::EvidenceExpired)
            .unwrap();
        match decision {
            AttestationFallbackDecision::Execute {
                attestation_status,
                warning,
            } => {
                assert_eq!(attestation_status, "degraded");
                assert!(warning.is_some());
                assert!(warning.unwrap().contains("expired"));
            }
            other => panic!("expected Execute, got {other:?}"),
        }
    }

    // -- AttestationFallbackManager: high-impact actions --

    #[test]
    fn high_impact_healthy_normal_executes() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::Quarantine, 100);
        let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
        assert!(matches!(
            decision,
            AttestationFallbackDecision::Execute { ref attestation_status, warning: None }
            if attestation_status == "valid"
        ));
    }

    #[test]
    fn high_impact_unhealthy_defers() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::Terminate, 100);
        let decision = mgr
            .evaluate_action(req, AttestationHealth::VerificationFailed)
            .unwrap();
        match decision {
            AttestationFallbackDecision::Deferred {
                queue_id,
                attestation_status,
                status,
                challenge_required,
                sandbox_required,
            } => {
                assert_eq!(queue_id, 0);
                assert_eq!(attestation_status, "degraded");
                assert_eq!(status, "attestation-pending");
                assert!(challenge_required);
                assert!(sandbox_required);
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
        assert_eq!(mgr.pending_decisions().len(), 1);
        assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    }

    #[test]
    fn high_impact_deferred_while_degraded_increments_queue_id() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        // First defer
        let req1 = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        // Second defer
        let req2 = attestation_request(AutonomousAction::Terminate, 200);
        let decision = mgr
            .evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        match decision {
            AttestationFallbackDecision::Deferred { queue_id, .. } => {
                assert_eq!(queue_id, 1);
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
        assert_eq!(mgr.pending_decisions().len(), 2);
    }

    // -- State transitions --

    #[test]
    fn state_transitions_normal_to_degraded_to_normal() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        assert_eq!(mgr.state(), AttestationFallbackState::Normal);

        // Degrade
        let req1 = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
            .unwrap();
        assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

        // Restore (healthy again, with a high-impact request)
        let req2 = attestation_request(AutonomousAction::Quarantine, 200);
        mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();
        assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    }

    #[test]
    fn transition_receipts_generated_for_state_changes() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());

        // Normal → Degraded
        let req1 = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
            .unwrap();
        assert!(!mgr.transition_receipts().is_empty());

        // Degraded → Restoring → Normal (two transitions)
        let req2 = attestation_request(AutonomousAction::MetricsEmission, 200);
        mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();
        // Normal→Degraded (1) + Degraded→Restoring (2) + Restoring→Normal (3) = 3
        assert_eq!(mgr.transition_receipts().len(), 3);
    }

    #[test]
    fn transition_receipts_verify_signature() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
            .unwrap();

        for receipt in mgr.transition_receipts() {
            receipt.verify().expect("receipt signature should be valid");
        }
    }

    // -- Recovery backlog --

    #[test]
    fn recovery_moves_pending_to_backlog() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());

        // Degrade and defer
        let req1 = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
            .unwrap();
        assert_eq!(mgr.pending_decisions().len(), 1);

        // Restore
        let req2 = attestation_request(AutonomousAction::MetricsEmission, 200);
        mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();

        assert!(mgr.pending_decisions().is_empty());
        let backlog = mgr.take_recovery_backlog();
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].status, "attestation-pending");
    }

    // -- Operator review escalation --

    #[test]
    fn operator_review_not_required_before_timeout() {
        let config = AttestationFallbackConfig {
            unavailable_timeout_ns: 1000,
            ..Default::default()
        };
        let mut mgr = AttestationFallbackManager::with_default_signing_key(config);

        // First request sets degraded_since_ns = 100
        let req1 = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        assert!(!mgr.operator_review_required());

        // 500ns later: still under timeout
        let req2 = attestation_request(AutonomousAction::Quarantine, 600);
        mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        assert!(!mgr.operator_review_required());
    }

    #[test]
    fn operator_review_required_after_timeout() {
        let config = AttestationFallbackConfig {
            unavailable_timeout_ns: 1000,
            ..Default::default()
        };
        let mut mgr = AttestationFallbackManager::with_default_signing_key(config);

        let req1 = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
            .unwrap();

        // 1100ns later: past timeout
        let req2 = attestation_request(AutonomousAction::Quarantine, 1200);
        mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        assert!(mgr.operator_review_required());
    }

    #[test]
    fn operator_review_cleared_on_recovery() {
        let config = AttestationFallbackConfig {
            unavailable_timeout_ns: 100,
            ..Default::default()
        };
        let mut mgr = AttestationFallbackManager::with_default_signing_key(config);

        let req1 = attestation_request(AutonomousAction::Quarantine, 0);
        mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        let req2 = attestation_request(AutonomousAction::Quarantine, 200);
        mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        assert!(mgr.operator_review_required());

        // Recover
        let req3 = attestation_request(AutonomousAction::MetricsEmission, 300);
        mgr.evaluate_action(req3, AttestationHealth::Valid).unwrap();
        assert!(!mgr.operator_review_required());
    }

    // -- Operator review only triggers for EvidenceUnavailable --

    #[test]
    fn operator_review_only_for_evidence_unavailable() {
        let config = AttestationFallbackConfig {
            unavailable_timeout_ns: 100,
            ..Default::default()
        };
        let mut mgr = AttestationFallbackManager::with_default_signing_key(config);

        // VerificationFailed past timeout does NOT trigger operator review
        let req1 = attestation_request(AutonomousAction::Quarantine, 0);
        mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
            .unwrap();
        let req2 = attestation_request(AutonomousAction::Quarantine, 500);
        mgr.evaluate_action(req2, AttestationHealth::VerificationFailed)
            .unwrap();
        assert!(!mgr.operator_review_required());
    }

    // -- Events --

    #[test]
    fn attestation_fallback_emits_structured_events() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::MetricsEmission, 100);
        mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();

        assert!(!mgr.events().is_empty());
        let event = &mgr.events()[0];
        assert_eq!(event.component, "attestation_safe_mode");
        assert_eq!(event.trace_id, "trace-a");
        assert!(!event.event.is_empty());
    }

    #[test]
    fn attestation_fallback_event_serde_roundtrip() {
        let event = AttestationFallbackEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "attestation_safe_mode".to_string(),
            event: "test_event".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: "detail".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AttestationFallbackEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -- QueuedAttestationDecision --

    #[test]
    fn queued_attestation_decision_serde_roundtrip() {
        let queued = QueuedAttestationDecision {
            queue_id: 5,
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            action: AutonomousAction::Quarantine,
            queued_at_ns: 12345,
            status: "attestation-pending".to_string(),
        };
        let json = serde_json::to_string(&queued).unwrap();
        let parsed: QueuedAttestationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(queued, parsed);
    }

    // -- AttestationFallbackDecision serde --

    #[test]
    fn attestation_fallback_decision_execute_serde() {
        let decision = AttestationFallbackDecision::Execute {
            attestation_status: "valid".to_string(),
            warning: Some("test warning".to_string()),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, parsed);
    }

    #[test]
    fn attestation_fallback_decision_deferred_serde() {
        let decision = AttestationFallbackDecision::Deferred {
            queue_id: 3,
            attestation_status: "degraded".to_string(),
            status: "attestation-pending".to_string(),
            challenge_required: true,
            sandbox_required: false,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, parsed);
    }

    // -- AttestationTransitionReceipt --

    #[test]
    fn attestation_transition_receipt_serde_roundtrip() {
        let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
        let req = attestation_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
            .unwrap();

        let receipt = &mgr.transition_receipts()[0];
        let json = serde_json::to_string(receipt).unwrap();
        let parsed: AttestationTransitionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, &parsed);
        parsed.verify().expect("deserialized receipt should verify");
    }

    // -- attestation_health_from_verdict --

    #[test]
    fn health_from_verdict_valid() {
        let verdict = passing_verdict();
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::Valid
        );
    }

    #[test]
    fn health_from_verdict_stale_warning() {
        let mut verdict = passing_verdict();
        verdict.warnings.push("attestation_data_stale".to_string());
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::EvidenceExpired
        );
    }

    #[test]
    fn health_from_verdict_quote_age_mismatch() {
        let mut verdict = passing_verdict();
        verdict.attestation.passed = false;
        verdict.attestation.error_code = Some("attestation_policy_quote_age_mismatch".to_string());
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::EvidenceExpired
        );
    }

    #[test]
    fn health_from_verdict_trust_root_missing() {
        let mut verdict = passing_verdict();
        verdict.attestation.passed = false;
        verdict.attestation.error_code = Some("attestation_trust_root_missing".to_string());
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::EvidenceUnavailable
        );
    }

    #[test]
    fn health_from_verdict_quote_digest_unavailable() {
        let mut verdict = passing_verdict();
        verdict.attestation.passed = false;
        verdict.attestation.error_code = Some("attestation_quote_digest_unavailable".to_string());
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::EvidenceUnavailable
        );
    }

    #[test]
    fn health_from_verdict_measurement_id_derivation_failed() {
        let mut verdict = passing_verdict();
        verdict.attestation.passed = false;
        verdict.attestation.error_code =
            Some("attestation_measurement_id_derivation_failed".to_string());
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::EvidenceUnavailable
        );
    }

    #[test]
    fn health_from_verdict_stale_data_failure_class() {
        let mut verdict = passing_verdict();
        verdict.passed = false;
        verdict.failure_class = Some(VerificationFailureClass::StaleData);
        verdict.attestation.passed = false;
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::EvidenceExpired
        );
    }

    #[test]
    fn health_from_verdict_generic_failure() {
        let mut verdict = passing_verdict();
        verdict.attestation.passed = false;
        verdict.attestation.error_code = Some("some_other_error".to_string());
        assert_eq!(
            attestation_health_from_verdict(&verdict),
            AttestationHealth::VerificationFailed
        );
    }

    // -- Determinism --

    #[test]
    fn attestation_fallback_deterministic_100_times() {
        let mut results = Vec::new();
        for _ in 0..100 {
            let mut mgr = AttestationFallbackManager::with_default_signing_key(Default::default());
            let req = attestation_request(AutonomousAction::Quarantine, 100);
            let decision = mgr
                .evaluate_action(req, AttestationHealth::VerificationFailed)
                .unwrap();
            results.push((mgr.state(), decision));
        }
        for r in &results[1..] {
            assert_eq!(r, &results[0], "attestation fallback must be deterministic");
        }
    }

    // -- Manager with custom signing key --

    #[test]
    fn manager_with_custom_signing_key() {
        let key = make_signing_key();
        let mgr = AttestationFallbackManager::new(Default::default(), key);
        assert_eq!(mgr.state(), AttestationFallbackState::Normal);
        assert_eq!(mgr.health(), AttestationHealth::Valid);
        assert!(!mgr.operator_review_required());
        assert!(mgr.pending_decisions().is_empty());
        assert!(mgr.transition_receipts().is_empty());
        assert!(mgr.events().is_empty());
    }

    // -- Config with challenge/sandbox disabled --

    #[test]
    fn config_no_challenge_no_sandbox() {
        let config = AttestationFallbackConfig {
            unavailable_timeout_ns: 1_000_000,
            challenge_on_fallback: false,
            sandbox_on_fallback: false,
        };
        let mut mgr = AttestationFallbackManager::with_default_signing_key(config);
        let req = attestation_request(AutonomousAction::Quarantine, 100);
        let decision = mgr
            .evaluate_action(req, AttestationHealth::EvidenceExpired)
            .unwrap();
        match decision {
            AttestationFallbackDecision::Deferred {
                challenge_required,
                sandbox_required,
                ..
            } => {
                assert!(!challenge_required);
                assert!(!sandbox_required);
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
    }

    // -- Full lifecycle --

    #[test]
    fn full_attestation_lifecycle() {
        let config = AttestationFallbackConfig {
            unavailable_timeout_ns: 500,
            ..Default::default()
        };
        let mut mgr = AttestationFallbackManager::with_default_signing_key(config);

        // 1. Normal: high-impact passes
        let req1 = attestation_request(AutonomousAction::Quarantine, 100);
        let d1 = mgr.evaluate_action(req1, AttestationHealth::Valid).unwrap();
        assert!(matches!(d1, AttestationFallbackDecision::Execute { .. }));
        assert_eq!(mgr.state(), AttestationFallbackState::Normal);

        // 2. Health degrades: high-impact deferred
        let req2 = attestation_request(AutonomousAction::Terminate, 200);
        let d2 = mgr
            .evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        assert!(matches!(d2, AttestationFallbackDecision::Deferred { .. }));
        assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

        // 3. Standard action still executes with warning
        let req3 = attestation_request(AutonomousAction::RoutineMonitoring, 300);
        let d3 = mgr
            .evaluate_action(req3, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        assert!(matches!(
            d3,
            AttestationFallbackDecision::Execute {
                warning: Some(_),
                ..
            }
        ));

        // 4. Timeout triggers operator review
        let req4 = attestation_request(AutonomousAction::Quarantine, 700);
        mgr.evaluate_action(req4, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        assert!(mgr.operator_review_required());

        // 5. Recovery: restoring → normal
        let req5 = attestation_request(AutonomousAction::MetricsEmission, 800);
        mgr.evaluate_action(req5, AttestationHealth::Valid).unwrap();
        assert_eq!(mgr.state(), AttestationFallbackState::Normal);
        assert!(!mgr.operator_review_required());

        // 6. Recovery backlog available
        let backlog = mgr.take_recovery_backlog();
        assert!(!backlog.is_empty());

        // 7. All receipts verify
        for receipt in mgr.transition_receipts() {
            receipt.verify().expect("receipt should verify");
        }
    }
}
