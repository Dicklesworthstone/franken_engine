//! Obligation-tracked channels for safety-critical two-phase protocols.
//!
//! Every message sent on an `ObligationChannel` creates a linear obligation
//! that must be explicitly resolved (committed or aborted). Unresolved
//! obligations are detected and escalatable.
//!
//! Plan references: Section 10.11 item 6, 9G.3 (linear-obligation discipline),
//! Top-10 #3 (deterministic evidence graph), #10 (provenance + revocation).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ObligationState — lifecycle of an obligation
// ---------------------------------------------------------------------------

/// State of a tracked obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationState {
    Pending,
    Committed,
    Aborted,
    Leaked,
}

impl fmt::Display for ObligationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Committed => write!(f, "committed"),
            Self::Aborted => write!(f, "aborted"),
            Self::Leaked => write!(f, "leaked"),
        }
    }
}

// ---------------------------------------------------------------------------
// AbortReason — why an obligation was aborted
// ---------------------------------------------------------------------------

/// Reason for aborting an obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    /// Timeout during drain phase.
    DrainTimeout,
    /// Upstream failure.
    UpstreamFailure,
    /// Policy violation.
    PolicyViolation,
    /// Explicit operator abort.
    OperatorAbort,
    /// Custom reason.
    Custom(String),
}

impl fmt::Display for AbortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DrainTimeout => write!(f, "drain_timeout"),
            Self::UpstreamFailure => write!(f, "upstream_failure"),
            Self::PolicyViolation => write!(f, "policy_violation"),
            Self::OperatorAbort => write!(f, "operator_abort"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationError — errors in obligation operations
// ---------------------------------------------------------------------------

/// Error from obligation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationError {
    /// Obligation not found.
    NotFound { obligation_id: u64 },
    /// Obligation already resolved.
    AlreadyResolved { obligation_id: u64 },
    /// Channel at backpressure limit.
    Backpressure { max_pending: usize },
    /// Obligation leaked (detected on drop without resolution).
    Leaked { obligation_id: u64 },
}

impl fmt::Display for ObligationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { obligation_id } => {
                write!(f, "obligation {obligation_id} not found")
            }
            Self::AlreadyResolved { obligation_id } => {
                write!(f, "obligation {obligation_id} already resolved")
            }
            Self::Backpressure { max_pending } => {
                write!(f, "backpressure: max {max_pending} pending obligations")
            }
            Self::Leaked { obligation_id } => {
                write!(f, "obligation {obligation_id} leaked")
            }
        }
    }
}

impl std::error::Error for ObligationError {}

// ---------------------------------------------------------------------------
// ObligationRecord — registry entry
// ---------------------------------------------------------------------------

/// Registry entry for a tracked obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationRecord {
    pub obligation_id: u64,
    pub created_at_tick: u64,
    pub creator_trace_id: String,
    pub state: ObligationState,
    pub resolution_evidence_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// ObligationEvent — structured evidence
// ---------------------------------------------------------------------------

/// Structured event for obligation lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationEvent {
    pub trace_id: String,
    pub channel_id: String,
    pub obligation_id: u64,
    pub state: ObligationState,
    pub resolution_type: Option<String>,
    pub evidence_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// ChannelConfig — configuration
// ---------------------------------------------------------------------------

/// Configuration for an obligation channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Maximum pending obligations before backpressure.
    pub max_pending: usize,
    /// If true, leaks are fatal (lab mode).
    pub lab_mode: bool,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            max_pending: 256,
            lab_mode: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ObligationChannel — the channel itself
// ---------------------------------------------------------------------------

/// An obligation-tracked channel for two-phase protocols.
///
/// Every `send` creates a pending obligation that must be resolved
/// via `commit` or `abort`. Unresolved obligations are detectable.
#[derive(Debug)]
pub struct ObligationChannel {
    pub channel_id: String,
    config: ChannelConfig,
    trace_id: String,
    registry: BTreeMap<u64, ObligationRecord>,
    next_obligation_id: u64,
    current_tick: u64,
    events: Vec<ObligationEvent>,
    leak_count: usize,
}

impl ObligationChannel {
    /// Create a new obligation channel.
    pub fn new(
        channel_id: impl Into<String>,
        trace_id: impl Into<String>,
        config: ChannelConfig,
    ) -> Self {
        Self {
            channel_id: channel_id.into(),
            config,
            trace_id: trace_id.into(),
            registry: BTreeMap::new(),
            next_obligation_id: 1,
            current_tick: 0,
            events: Vec::new(),
            leak_count: 0,
        }
    }

    /// Set current virtual tick (for deterministic timestamps).
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Send a message, creating a pending obligation. Returns obligation_id.
    pub fn send(&mut self, creator_trace_id: &str) -> Result<u64, ObligationError> {
        if self.pending_count() >= self.config.max_pending {
            return Err(ObligationError::Backpressure {
                max_pending: self.config.max_pending,
            });
        }

        let id = self.next_obligation_id;
        self.next_obligation_id += 1;

        self.registry.insert(
            id,
            ObligationRecord {
                obligation_id: id,
                created_at_tick: self.current_tick,
                creator_trace_id: creator_trace_id.to_string(),
                state: ObligationState::Pending,
                resolution_evidence_hash: None,
            },
        );

        self.emit_event(id, ObligationState::Pending, None, None);
        Ok(id)
    }

    /// Commit an obligation (mark as successfully resolved).
    pub fn commit(
        &mut self,
        obligation_id: u64,
        evidence_hash: &str,
    ) -> Result<(), ObligationError> {
        let record = self
            .registry
            .get_mut(&obligation_id)
            .ok_or(ObligationError::NotFound { obligation_id })?;

        if record.state != ObligationState::Pending {
            return Err(ObligationError::AlreadyResolved { obligation_id });
        }

        record.state = ObligationState::Committed;
        record.resolution_evidence_hash = Some(evidence_hash.to_string());

        self.emit_event(
            obligation_id,
            ObligationState::Committed,
            Some("commit"),
            Some(evidence_hash),
        );
        Ok(())
    }

    /// Abort an obligation (mark as rolled back).
    pub fn abort(
        &mut self,
        obligation_id: u64,
        _reason: &AbortReason,
        evidence_hash: &str,
    ) -> Result<(), ObligationError> {
        let record = self
            .registry
            .get_mut(&obligation_id)
            .ok_or(ObligationError::NotFound { obligation_id })?;

        if record.state != ObligationState::Pending {
            return Err(ObligationError::AlreadyResolved { obligation_id });
        }

        record.state = ObligationState::Aborted;
        record.resolution_evidence_hash = Some(evidence_hash.to_string());

        self.emit_event(
            obligation_id,
            ObligationState::Aborted,
            Some("abort"),
            Some(evidence_hash),
        );
        Ok(())
    }

    /// Mark an obligation as leaked (detected on drop without resolution).
    pub fn mark_leaked(&mut self, obligation_id: u64) -> Result<(), ObligationError> {
        let record = self
            .registry
            .get_mut(&obligation_id)
            .ok_or(ObligationError::NotFound { obligation_id })?;

        if record.state != ObligationState::Pending {
            return Err(ObligationError::AlreadyResolved { obligation_id });
        }

        record.state = ObligationState::Leaked;
        self.leak_count += 1;

        self.emit_event(obligation_id, ObligationState::Leaked, Some("leak"), None);
        Ok(())
    }

    /// Count of pending (unresolved) obligations.
    pub fn pending_count(&self) -> usize {
        self.registry
            .values()
            .filter(|r| r.state == ObligationState::Pending)
            .count()
    }

    /// Oldest pending obligation (by creation tick).
    pub fn oldest_pending(&self) -> Option<&ObligationRecord> {
        self.registry
            .values()
            .filter(|r| r.state == ObligationState::Pending)
            .min_by_key(|r| r.created_at_tick)
    }

    /// Total obligations (all states).
    pub fn total_count(&self) -> usize {
        self.registry.len()
    }

    /// Number of leaks detected.
    pub fn leak_count(&self) -> usize {
        self.leak_count
    }

    /// Whether this channel is in lab mode (leaks are fatal).
    pub fn is_lab_mode(&self) -> bool {
        self.config.lab_mode
    }

    /// Wait for drain: returns true if all obligations resolved, false if pending remain.
    pub fn drain_check(&self) -> bool {
        self.pending_count() == 0
    }

    /// Force-abort all pending obligations (for drain timeout escalation).
    pub fn force_abort_all_pending(&mut self, evidence_hash: &str) -> usize {
        let pending_ids: Vec<u64> = self
            .registry
            .iter()
            .filter(|(_, r)| r.state == ObligationState::Pending)
            .map(|(&id, _)| id)
            .collect();

        let count = pending_ids.len();
        for id in pending_ids {
            let _ = self.abort(id, &AbortReason::DrainTimeout, evidence_hash);
        }
        count
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<ObligationEvent> {
        std::mem::take(&mut self.events)
    }

    fn emit_event(
        &mut self,
        obligation_id: u64,
        state: ObligationState,
        resolution_type: Option<&str>,
        evidence_hash: Option<&str>,
    ) {
        self.events.push(ObligationEvent {
            trace_id: self.trace_id.clone(),
            channel_id: self.channel_id.clone(),
            obligation_id,
            state,
            resolution_type: resolution_type.map(String::from),
            evidence_hash: evidence_hash.map(String::from),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_channel() -> ObligationChannel {
        ObligationChannel::new(
            "chan-1",
            "trace-1",
            ChannelConfig {
                max_pending: 10,
                lab_mode: false,
            },
        )
    }

    // -- ObligationState --

    #[test]
    fn state_display() {
        assert_eq!(ObligationState::Pending.to_string(), "pending");
        assert_eq!(ObligationState::Committed.to_string(), "committed");
        assert_eq!(ObligationState::Aborted.to_string(), "aborted");
        assert_eq!(ObligationState::Leaked.to_string(), "leaked");
    }

    // -- AbortReason --

    #[test]
    fn abort_reason_display() {
        assert_eq!(AbortReason::DrainTimeout.to_string(), "drain_timeout");
        assert_eq!(AbortReason::UpstreamFailure.to_string(), "upstream_failure");
        assert_eq!(AbortReason::Custom("x".to_string()).to_string(), "custom:x");
    }

    // -- Send / Commit / Abort --

    #[test]
    fn send_creates_pending_obligation() {
        let mut chan = test_channel();
        let id = chan
            .send("trace-a")
            .expect("operation should succeed for valid inputs");
        assert_eq!(id, 1);
        assert_eq!(chan.pending_count(), 1);
    }

    #[test]
    fn commit_resolves_obligation() {
        let mut chan = test_channel();
        let id = chan
            .send("trace-a")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "hash-1")
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.pending_count(), 0);
    }

    #[test]
    fn abort_resolves_obligation() {
        let mut chan = test_channel();
        let id = chan
            .send("trace-a")
            .expect("operation should succeed for valid inputs");
        chan.abort(id, &AbortReason::UpstreamFailure, "hash-2")
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.pending_count(), 0);
    }

    #[test]
    fn double_commit_fails() {
        let mut chan = test_channel();
        let id = chan
            .send("trace-a")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "h")
            .expect("operation should succeed for valid inputs");
        let err = chan.commit(id, "h").unwrap_err();
        assert_eq!(err, ObligationError::AlreadyResolved { obligation_id: id });
    }

    #[test]
    fn commit_after_abort_fails() {
        let mut chan = test_channel();
        let id = chan
            .send("trace-a")
            .expect("operation should succeed for valid inputs");
        chan.abort(id, &AbortReason::DrainTimeout, "h")
            .expect("operation should succeed for valid inputs");
        assert!(chan.commit(id, "h").is_err());
    }

    #[test]
    fn commit_nonexistent_fails() {
        let mut chan = test_channel();
        let err = chan.commit(999, "h").unwrap_err();
        assert_eq!(err, ObligationError::NotFound { obligation_id: 999 });
    }

    // -- Backpressure --

    #[test]
    fn backpressure_at_limit() {
        let mut chan = ObligationChannel::new(
            "chan",
            "t",
            ChannelConfig {
                max_pending: 3,
                lab_mode: false,
            },
        );
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");

        let err = chan.send("t").unwrap_err();
        assert_eq!(err, ObligationError::Backpressure { max_pending: 3 });
    }

    #[test]
    fn backpressure_clears_after_resolution() {
        let mut chan = ObligationChannel::new(
            "chan",
            "t",
            ChannelConfig {
                max_pending: 2,
                lab_mode: false,
            },
        );
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        assert!(chan.send("t").is_err());

        chan.commit(id1, "h")
            .expect("operation should succeed for valid inputs");
        assert!(chan.send("t").is_ok());
    }

    // -- Leak detection --

    #[test]
    fn mark_leaked() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.mark_leaked(id)
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.leak_count(), 1);
        assert_eq!(chan.pending_count(), 0);
    }

    #[test]
    fn leak_already_resolved_fails() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "h")
            .expect("operation should succeed for valid inputs");
        assert!(chan.mark_leaked(id).is_err());
    }

    // -- Oldest pending --

    #[test]
    fn oldest_pending_returns_earliest() {
        let mut chan = test_channel();
        chan.set_tick(10);
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.set_tick(20);
        chan.send("t")
            .expect("operation should succeed for valid inputs");

        let oldest = chan
            .oldest_pending()
            .expect("operation should succeed for valid inputs");
        assert_eq!(oldest.created_at_tick, 10);
    }

    #[test]
    fn oldest_pending_none_when_empty() {
        let chan = test_channel();
        assert!(chan.oldest_pending().is_none());
    }

    // -- Drain --

    #[test]
    fn drain_check_true_when_no_pending() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "h")
            .expect("operation should succeed for valid inputs");
        assert!(chan.drain_check());
    }

    #[test]
    fn drain_check_false_when_pending() {
        let mut chan = test_channel();
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        assert!(!chan.drain_check());
    }

    #[test]
    fn force_abort_all_pending() {
        let mut chan = test_channel();
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        let id3 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id3, "h")
            .expect("operation should succeed for valid inputs");

        let aborted = chan.force_abort_all_pending("timeout-hash");
        assert_eq!(aborted, 2);
        assert!(chan.drain_check());
    }

    // -- Events --

    #[test]
    fn events_emitted_on_lifecycle() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "h")
            .expect("operation should succeed for valid inputs");

        let events = chan.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].state, ObligationState::Pending);
        assert_eq!(events[1].state, ObligationState::Committed);
    }

    #[test]
    fn event_carries_correct_fields() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "evidence-hash")
            .expect("operation should succeed for valid inputs");

        let events = chan.drain_events();
        let commit_event = &events[1];
        assert_eq!(commit_event.trace_id, "trace-1");
        assert_eq!(commit_event.channel_id, "chan-1");
        assert_eq!(commit_event.obligation_id, 1);
        assert_eq!(commit_event.resolution_type, Some("commit".to_string()));
        assert_eq!(
            commit_event.evidence_hash,
            Some("evidence-hash".to_string())
        );
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<ObligationEvent> {
            let mut chan = test_channel();
            chan.set_tick(10);
            let id1 = chan
                .send("t")
                .expect("operation should succeed for valid inputs");
            chan.set_tick(20);
            let id2 = chan
                .send("t")
                .expect("operation should succeed for valid inputs");
            chan.commit(id1, "h1")
                .expect("operation should succeed for valid inputs");
            chan.abort(id2, &AbortReason::DrainTimeout, "h2")
                .expect("operation should succeed for valid inputs");
            chan.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- ObligationError display --

    #[test]
    fn error_display() {
        assert!(
            ObligationError::NotFound { obligation_id: 1 }
                .to_string()
                .contains("not found")
        );
        assert!(
            ObligationError::AlreadyResolved { obligation_id: 1 }
                .to_string()
                .contains("already resolved")
        );
        assert!(
            ObligationError::Backpressure { max_pending: 10 }
                .to_string()
                .contains("backpressure")
        );
        assert!(
            ObligationError::Leaked { obligation_id: 1 }
                .to_string()
                .contains("leaked")
        );
    }

    // -- Lab mode --

    #[test]
    fn lab_mode_flag() {
        let chan = ObligationChannel::new(
            "chan",
            "t",
            ChannelConfig {
                max_pending: 10,
                lab_mode: true,
            },
        );
        assert!(chan.is_lab_mode());
    }

    // -- Serialization --

    #[test]
    fn obligation_record_serialization_round_trip() {
        let record = ObligationRecord {
            obligation_id: 1,
            created_at_tick: 100,
            creator_trace_id: "t".to_string(),
            state: ObligationState::Committed,
            resolution_evidence_hash: Some("h".to_string()),
        };
        let json = serde_json::to_string(&record).expect("serialize derived Serialize");
        let restored: ObligationRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(record, restored);
    }

    #[test]
    fn obligation_event_serialization_round_trip() {
        let event = ObligationEvent {
            trace_id: "t".to_string(),
            channel_id: "c".to_string(),
            obligation_id: 1,
            state: ObligationState::Committed,
            resolution_type: Some("commit".to_string()),
            evidence_hash: Some("h".to_string()),
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: ObligationEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    #[test]
    fn channel_config_serialization_round_trip() {
        let config = ChannelConfig::default();
        let json = serde_json::to_string(&config).expect("serialize derived Serialize");
        let restored: ChannelConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(config, restored);
    }

    // -- Multiple obligations --

    // -- Enrichment: serde, std::error --

    #[test]
    fn obligation_state_serde_all_variants() {
        for state in [
            ObligationState::Pending,
            ObligationState::Committed,
            ObligationState::Aborted,
            ObligationState::Leaked,
        ] {
            let json = serde_json::to_string(&state).expect("serialize derived Serialize");
            let restored: ObligationState =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(state, restored);
        }
    }

    #[test]
    fn abort_reason_serde_all_variants() {
        let reasons = vec![
            AbortReason::DrainTimeout,
            AbortReason::UpstreamFailure,
            AbortReason::PolicyViolation,
            AbortReason::OperatorAbort,
            AbortReason::Custom("custom-reason".to_string()),
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).expect("serialize derived Serialize");
            let restored: AbortReason =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*reason, restored);
        }
    }

    #[test]
    fn obligation_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ObligationError::NotFound { obligation_id: 1 }),
            Box::new(ObligationError::AlreadyResolved { obligation_id: 2 }),
            Box::new(ObligationError::Backpressure { max_pending: 10 }),
            Box::new(ObligationError::Leaked { obligation_id: 3 }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 variants produce distinct messages"
        );
    }

    #[test]
    fn multiple_obligations_independent() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id3 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");

        chan.commit(id1, "h1")
            .expect("operation should succeed for valid inputs");
        chan.abort(id2, &AbortReason::OperatorAbort, "h2")
            .expect("operation should succeed for valid inputs");
        chan.mark_leaked(id3)
            .expect("operation should succeed for valid inputs");

        assert_eq!(chan.pending_count(), 0);
        assert_eq!(chan.total_count(), 3);
        assert_eq!(chan.leak_count(), 1);
    }

    // --- enrichment tests ---

    #[test]
    fn obligation_state_display_all_variants() {
        let states = [
            (ObligationState::Pending, "pending"),
            (ObligationState::Committed, "committed"),
            (ObligationState::Aborted, "aborted"),
            (ObligationState::Leaked, "leaked"),
        ];
        for (state, expected) in &states {
            assert_eq!(state.to_string(), *expected);
        }
    }

    #[test]
    fn abort_reason_display_all_variants() {
        assert_eq!(AbortReason::DrainTimeout.to_string(), "drain_timeout");
        assert_eq!(AbortReason::UpstreamFailure.to_string(), "upstream_failure");
        assert_eq!(AbortReason::PolicyViolation.to_string(), "policy_violation");
        assert_eq!(AbortReason::OperatorAbort.to_string(), "operator_abort");
        assert_eq!(
            AbortReason::Custom("foo".to_string()).to_string(),
            "custom:foo"
        );
    }

    #[test]
    fn channel_config_default_values() {
        let cfg = ChannelConfig::default();
        assert_eq!(cfg.max_pending, 256);
        assert!(!cfg.lab_mode);
    }

    #[test]
    fn obligation_ids_are_sequential() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id3 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut chan = test_channel();
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        assert!(!chan.drain_events().is_empty());
        assert!(chan.drain_events().is_empty());
    }

    #[test]
    fn commit_nonexistent_obligation_fails() {
        let mut chan = test_channel();
        let err = chan.commit(999, "h").unwrap_err();
        assert!(matches!(
            err,
            ObligationError::NotFound { obligation_id: 999 }
        ));
    }

    #[test]
    fn abort_nonexistent_obligation_fails() {
        let mut chan = test_channel();
        let err = chan
            .abort(999, &AbortReason::DrainTimeout, "h")
            .unwrap_err();
        assert!(matches!(
            err,
            ObligationError::NotFound { obligation_id: 999 }
        ));
    }

    #[test]
    fn double_commit_returns_already_resolved() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "h1")
            .expect("operation should succeed for valid inputs");
        let err = chan.commit(id, "h2").unwrap_err();
        assert!(matches!(err, ObligationError::AlreadyResolved { .. }));
    }

    #[test]
    fn obligation_error_serde_all_variants() {
        let errors = vec![
            ObligationError::NotFound { obligation_id: 1 },
            ObligationError::AlreadyResolved { obligation_id: 2 },
            ObligationError::Backpressure { max_pending: 10 },
            ObligationError::Leaked { obligation_id: 3 },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let restored: ObligationError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, edge cases, error
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_state_display_all_unique() {
        let states = [
            ObligationState::Pending,
            ObligationState::Committed,
            ObligationState::Aborted,
            ObligationState::Leaked,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in &states {
            seen.insert(s.to_string());
        }
        assert_eq!(
            seen.len(),
            4,
            "all 4 ObligationState Display strings must be unique"
        );
    }

    #[test]
    fn abort_reason_display_all_unique() {
        let reasons = [
            AbortReason::DrainTimeout,
            AbortReason::UpstreamFailure,
            AbortReason::PolicyViolation,
            AbortReason::OperatorAbort,
            AbortReason::Custom("test".to_string()),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in &reasons {
            seen.insert(r.to_string());
        }
        assert_eq!(
            seen.len(),
            5,
            "all 5 AbortReason Display strings must be unique"
        );
    }

    #[test]
    fn obligation_error_source_is_none() {
        let err = ObligationError::NotFound { obligation_id: 1 };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn channel_total_count_includes_all_states() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id3 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id1, "h")
            .expect("operation should succeed for valid inputs");
        chan.abort(id2, &AbortReason::DrainTimeout, "h")
            .expect("operation should succeed for valid inputs");
        chan.mark_leaked(id3)
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.total_count(), 3);
        assert_eq!(chan.pending_count(), 0);
    }

    #[test]
    fn force_abort_all_pending_with_no_pending() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id, "h")
            .expect("operation should succeed for valid inputs");
        let aborted = chan.force_abort_all_pending("timeout-hash");
        assert_eq!(aborted, 0);
    }

    #[test]
    fn send_after_drain_check_true() {
        let mut chan = test_channel();
        assert!(chan.drain_check());
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        assert!(!chan.drain_check());
        chan.commit(id, "h")
            .expect("operation should succeed for valid inputs");
        assert!(chan.drain_check());
    }

    #[test]
    fn mark_leaked_nonexistent_fails() {
        let mut chan = test_channel();
        let err = chan.mark_leaked(999).unwrap_err();
        assert!(matches!(
            err,
            ObligationError::NotFound { obligation_id: 999 }
        ));
    }

    #[test]
    fn oldest_pending_skips_resolved() {
        let mut chan = test_channel();
        chan.set_tick(10);
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.set_tick(20);
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id1, "h")
            .expect("operation should succeed for valid inputs");

        let oldest = chan
            .oldest_pending()
            .expect("operation should succeed for valid inputs");
        assert_eq!(oldest.created_at_tick, 20);
    }

    #[test]
    fn abort_event_has_correct_resolution_type() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.abort(id, &AbortReason::PolicyViolation, "h")
            .expect("operation should succeed for valid inputs");
        let events = chan.drain_events();
        let abort_event = events
            .iter()
            .find(|e| e.state == ObligationState::Aborted)
            .expect("operation should succeed for valid inputs");
        assert_eq!(abort_event.resolution_type, Some("abort".to_string()));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON fields, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_record_clone_equality() {
        let rec = ObligationRecord {
            obligation_id: 42,
            created_at_tick: 100,
            creator_trace_id: "trace-x".to_string(),
            state: ObligationState::Committed,
            resolution_evidence_hash: Some("hash-abc".to_string()),
        };
        let cloned = rec.clone();
        assert_eq!(rec, cloned);
    }

    #[test]
    fn obligation_event_clone_equality() {
        let evt = ObligationEvent {
            trace_id: "t1".to_string(),
            channel_id: "c1".to_string(),
            obligation_id: 7,
            state: ObligationState::Aborted,
            resolution_type: Some("abort".to_string()),
            evidence_hash: Some("ev-hash".to_string()),
        };
        let cloned = evt.clone();
        assert_eq!(evt, cloned);
    }

    #[test]
    fn channel_config_clone_equality() {
        let cfg = ChannelConfig {
            max_pending: 128,
            lab_mode: true,
        };
        let cloned = cfg.clone();
        assert_eq!(cfg, cloned);
    }

    #[test]
    fn abort_reason_clone_equality() {
        let reasons = [
            AbortReason::DrainTimeout,
            AbortReason::UpstreamFailure,
            AbortReason::PolicyViolation,
            AbortReason::OperatorAbort,
            AbortReason::Custom("reason-x".to_string()),
        ];
        for reason in &reasons {
            let cloned = reason.clone();
            assert_eq!(*reason, cloned);
        }
    }

    #[test]
    fn obligation_record_json_field_presence() {
        let rec = ObligationRecord {
            obligation_id: 1,
            created_at_tick: 50,
            creator_trace_id: "tr".to_string(),
            state: ObligationState::Pending,
            resolution_evidence_hash: None,
        };
        let json = serde_json::to_string(&rec).expect("serialize derived Serialize");
        assert!(json.contains("\"obligation_id\""));
        assert!(json.contains("\"created_at_tick\""));
        assert!(json.contains("\"creator_trace_id\""));
        assert!(json.contains("\"state\""));
        assert!(json.contains("\"resolution_evidence_hash\""));
    }

    #[test]
    fn obligation_event_json_field_presence() {
        let evt = ObligationEvent {
            trace_id: "t".to_string(),
            channel_id: "c".to_string(),
            obligation_id: 1,
            state: ObligationState::Leaked,
            resolution_type: None,
            evidence_hash: None,
        };
        let json = serde_json::to_string(&evt).expect("serialize derived Serialize");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"channel_id\""));
        assert!(json.contains("\"obligation_id\""));
        assert!(json.contains("\"state\""));
        assert!(json.contains("\"resolution_type\""));
        assert!(json.contains("\"evidence_hash\""));
    }

    #[test]
    fn set_tick_updates_created_at_tick() {
        let mut chan = test_channel();
        chan.set_tick(500);
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let oldest = chan
            .oldest_pending()
            .expect("operation should succeed for valid inputs");
        assert_eq!(oldest.obligation_id, id);
        assert_eq!(oldest.created_at_tick, 500);
    }

    #[test]
    fn force_abort_all_pending_emits_events_for_each() {
        let mut chan = test_channel();
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.drain_events(); // clear send events
        chan.force_abort_all_pending("timeout-h");
        let events = chan.drain_events();
        assert_eq!(events.len(), 3);
        for evt in &events {
            assert_eq!(evt.state, ObligationState::Aborted);
            assert_eq!(evt.resolution_type, Some("abort".to_string()));
        }
    }

    #[test]
    fn leak_event_has_resolution_type_leak() {
        let mut chan = test_channel();
        let id = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.drain_events(); // clear send event
        chan.mark_leaked(id)
            .expect("operation should succeed for valid inputs");
        let events = chan.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].state, ObligationState::Leaked);
        assert_eq!(events[0].resolution_type, Some("leak".to_string()));
        assert_eq!(events[0].evidence_hash, None);
    }

    #[test]
    fn multiple_leaks_increment_count() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id3 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.mark_leaked(id1)
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.leak_count(), 1);
        chan.mark_leaked(id2)
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.leak_count(), 2);
        chan.mark_leaked(id3)
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.leak_count(), 3);
    }

    #[test]
    fn backpressure_ignores_resolved_obligations() {
        let mut chan = ObligationChannel::new(
            "chan",
            "t",
            ChannelConfig {
                max_pending: 2,
                lab_mode: false,
            },
        );
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id1, "h")
            .expect("operation should succeed for valid inputs");
        chan.abort(id2, &AbortReason::DrainTimeout, "h")
            .expect("operation should succeed for valid inputs");
        // Both resolved, total_count is 2 but pending_count is 0
        assert_eq!(chan.total_count(), 2);
        // Should allow 2 more sends since only pending counts
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        assert!(chan.send("t").is_err());
    }

    #[test]
    fn pending_event_has_no_resolution_type() {
        let mut chan = test_channel();
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        let events = chan.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].state, ObligationState::Pending);
        assert_eq!(events[0].resolution_type, None);
        assert_eq!(events[0].evidence_hash, None);
    }

    #[test]
    fn abort_reason_custom_empty_string_display() {
        let reason = AbortReason::Custom(String::new());
        assert_eq!(reason.to_string(), "custom:");
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn obligation_state_copy_semantics() {
        let a = ObligationState::Pending;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn abort_reason_custom_long_string_serde() {
        let reason = AbortReason::Custom("a".repeat(1000));
        let json = serde_json::to_string(&reason).expect("serialize derived Serialize");
        let back: AbortReason = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(reason, back);
    }

    #[test]
    fn obligation_error_not_found_display_contains_id() {
        let err = ObligationError::NotFound { obligation_id: 42 };
        let msg = err.to_string();
        assert!(msg.contains("42"));
    }

    #[test]
    fn obligation_error_already_resolved_display_contains_id() {
        let err = ObligationError::AlreadyResolved { obligation_id: 77 };
        let msg = err.to_string();
        assert!(msg.contains("77"));
    }

    #[test]
    fn obligation_error_backpressure_display_contains_limit() {
        let err = ObligationError::Backpressure { max_pending: 256 };
        let msg = err.to_string();
        assert!(msg.contains("256"));
    }

    #[test]
    fn obligation_error_leaked_display_contains_id() {
        let err = ObligationError::Leaked { obligation_id: 99 };
        let msg = err.to_string();
        assert!(msg.contains("99"));
    }

    #[test]
    fn channel_config_lab_mode_true_serde() {
        let cfg = ChannelConfig {
            max_pending: 50,
            lab_mode: true,
        };
        let json = serde_json::to_string(&cfg).expect("serialize derived Serialize");
        let back: ChannelConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(cfg, back);
    }

    #[test]
    fn obligation_record_with_none_evidence_serde() {
        let rec = ObligationRecord {
            obligation_id: 1,
            created_at_tick: 0,
            creator_trace_id: String::new(),
            state: ObligationState::Pending,
            resolution_evidence_hash: None,
        };
        let json = serde_json::to_string(&rec).expect("serialize derived Serialize");
        let back: ObligationRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(rec, back);
    }

    #[test]
    fn obligation_record_clone_independence_mutation() {
        let rec = ObligationRecord {
            obligation_id: 1,
            created_at_tick: 100,
            creator_trace_id: "trace-x".into(),
            state: ObligationState::Pending,
            resolution_evidence_hash: None,
        };
        let mut cloned = rec.clone();
        cloned.state = ObligationState::Committed;
        cloned.resolution_evidence_hash = Some("hash".into());
        assert_ne!(rec.state, cloned.state);
    }

    #[test]
    fn obligation_event_clone_independence_mutation() {
        let evt = ObligationEvent {
            trace_id: "t1".into(),
            channel_id: "c1".into(),
            obligation_id: 1,
            state: ObligationState::Pending,
            resolution_type: None,
            evidence_hash: None,
        };
        let mut cloned = evt.clone();
        cloned.resolution_type = Some("commit".into());
        assert_ne!(evt.resolution_type, cloned.resolution_type);
    }

    #[test]
    fn channel_config_clone_independence_mutation() {
        let cfg = ChannelConfig {
            max_pending: 100,
            lab_mode: false,
        };
        let mut cloned = cfg.clone();
        cloned.max_pending = 999;
        cloned.lab_mode = true;
        assert_ne!(cfg.max_pending, cloned.max_pending);
    }

    #[test]
    fn stress_send_commit_20_obligations() {
        let mut chan = ObligationChannel::new(
            "stress",
            "t",
            ChannelConfig {
                max_pending: 20,
                lab_mode: false,
            },
        );
        let mut ids = Vec::new();
        for i in 0..20 {
            chan.set_tick(i as u64);
            ids.push(
                chan.send("t")
                    .expect("operation should succeed for valid inputs"),
            );
        }
        assert_eq!(chan.pending_count(), 20);
        assert!(chan.send("t").is_err());
        for id in &ids {
            chan.commit(*id, "h")
                .expect("operation should succeed for valid inputs");
        }
        assert_eq!(chan.pending_count(), 0);
        assert_eq!(chan.total_count(), 20);
    }

    #[test]
    fn stress_interleaved_send_commit_abort() {
        let mut chan = test_channel();
        for i in 0u64..30 {
            chan.set_tick(i);
            let id = chan
                .send("t")
                .expect("operation should succeed for valid inputs");
            if i % 3 == 0 {
                chan.abort(id, &AbortReason::OperatorAbort, "h")
                    .expect("operation should succeed for valid inputs");
            } else {
                chan.commit(id, "h")
                    .expect("operation should succeed for valid inputs");
            }
        }
        assert_eq!(chan.pending_count(), 0);
        assert_eq!(chan.total_count(), 30);
    }

    #[test]
    fn deterministic_replay_complex_lifecycle() {
        let run = || -> Vec<ObligationEvent> {
            let mut chan = ObligationChannel::new(
                "replay-chan",
                "replay-trace",
                ChannelConfig {
                    max_pending: 10,
                    lab_mode: true,
                },
            );
            chan.set_tick(100);
            let id1 = chan
                .send("t")
                .expect("operation should succeed for valid inputs");
            chan.set_tick(200);
            let id2 = chan
                .send("t")
                .expect("operation should succeed for valid inputs");
            chan.set_tick(300);
            let id3 = chan
                .send("t")
                .expect("operation should succeed for valid inputs");
            chan.commit(id1, "h1")
                .expect("operation should succeed for valid inputs");
            chan.mark_leaked(id2)
                .expect("operation should succeed for valid inputs");
            chan.abort(id3, &AbortReason::PolicyViolation, "h3")
                .expect("operation should succeed for valid inputs");
            chan.drain_events()
        };
        let events1 = run();
        let events2 = run();
        assert_eq!(events1.len(), events2.len());
        for (a, b) in events1.iter().zip(events2.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn channel_id_propagates_to_events() {
        let mut chan = ObligationChannel::new("my-channel", "my-trace", ChannelConfig::default());
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        let events = chan.drain_events();
        assert_eq!(events[0].channel_id, "my-channel");
        assert_eq!(events[0].trace_id, "my-trace");
    }

    #[test]
    fn oldest_pending_after_all_resolved_is_none() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id1, "h")
            .expect("operation should succeed for valid inputs");
        chan.commit(id2, "h")
            .expect("operation should succeed for valid inputs");
        assert!(chan.oldest_pending().is_none());
    }

    #[test]
    fn force_abort_skips_already_committed() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let _id3 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id1, "h")
            .expect("operation should succeed for valid inputs");
        chan.mark_leaked(id2)
            .expect("operation should succeed for valid inputs");
        let aborted = chan.force_abort_all_pending("timeout");
        assert_eq!(aborted, 1);
        assert!(chan.drain_check());
    }

    #[test]
    fn send_with_empty_creator_trace_id() {
        let mut chan = test_channel();
        let id = chan
            .send("")
            .expect("operation should succeed for valid inputs");
        let oldest = chan
            .oldest_pending()
            .expect("operation should succeed for valid inputs");
        assert_eq!(oldest.obligation_id, id);
        assert_eq!(oldest.creator_trace_id, "");
    }

    #[test]
    fn drain_then_new_events_accumulate() {
        let mut chan = test_channel();
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        let batch1 = chan.drain_events();
        assert_eq!(batch1.len(), 1);
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        let batch2 = chan.drain_events();
        assert_eq!(batch2.len(), 2);
    }

    #[test]
    fn abort_reason_serde_custom_special_chars() {
        let reason = AbortReason::Custom("special: \"chars\" \n\t".into());
        let json = serde_json::to_string(&reason).expect("serialize derived Serialize");
        let back: AbortReason = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(reason, back);
    }

    #[test]
    fn obligation_error_serde_backpressure_boundary() {
        let err = ObligationError::Backpressure {
            max_pending: usize::MAX,
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: ObligationError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, back);
    }

    #[test]
    fn channel_config_max_pending_zero_blocks_all() {
        let mut chan = ObligationChannel::new(
            "zero",
            "t",
            ChannelConfig {
                max_pending: 0,
                lab_mode: false,
            },
        );
        let err = chan.send("t").unwrap_err();
        assert!(matches!(
            err,
            ObligationError::Backpressure { max_pending: 0 }
        ));
    }

    #[test]
    fn multiple_channels_independent_state() {
        let mut chan1 = ObligationChannel::new("c1", "t1", ChannelConfig::default());
        let mut chan2 = ObligationChannel::new("c2", "t2", ChannelConfig::default());
        let id1 = chan1
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan2
            .send("t")
            .expect("operation should succeed for valid inputs");
        assert_eq!(id1, 1);
        assert_eq!(id2, 1);
        chan1
            .commit(id1, "h")
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan1.pending_count(), 0);
        assert_eq!(chan2.pending_count(), 1);
    }

    #[test]
    fn leak_count_accumulates_across_ops() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.mark_leaked(id1)
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id2, "h")
            .expect("operation should succeed for valid inputs");
        let id3 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.mark_leaked(id3)
            .expect("operation should succeed for valid inputs");
        assert_eq!(chan.leak_count(), 2);
    }

    #[test]
    fn event_obligation_ids_match_send_ids() {
        let mut chan = test_channel();
        let id1 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        let id2 = chan
            .send("t")
            .expect("operation should succeed for valid inputs");
        chan.commit(id1, "h")
            .expect("operation should succeed for valid inputs");
        let events = chan.drain_events();
        let event_ids: Vec<u64> = events.iter().map(|e| e.obligation_id).collect();
        assert_eq!(event_ids, vec![id1, id2, id1]);
    }

    #[test]
    fn obligation_state_all_variants_distinct() {
        let states = [
            ObligationState::Pending,
            ObligationState::Committed,
            ObligationState::Aborted,
            ObligationState::Leaked,
        ];
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
    }

    #[test]
    fn obligation_error_not_found_zero_id_serde() {
        let err = ObligationError::NotFound { obligation_id: 0 };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: ObligationError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, back);
    }

    #[test]
    fn obligation_state_serde_leaked() {
        let state = ObligationState::Leaked;
        let json = serde_json::to_string(&state).expect("serialize derived Serialize");
        let back: ObligationState =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(state, back);
    }

    #[test]
    fn lab_mode_false_by_default() {
        let chan = test_channel();
        assert!(!chan.is_lab_mode());
    }

    #[test]
    fn tick_monotonicity_in_oldest() {
        let mut chan = test_channel();
        chan.set_tick(100);
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        chan.set_tick(50);
        chan.send("t")
            .expect("operation should succeed for valid inputs");
        let oldest = chan
            .oldest_pending()
            .expect("operation should succeed for valid inputs");
        assert_eq!(oldest.created_at_tick, 50);
    }
}
