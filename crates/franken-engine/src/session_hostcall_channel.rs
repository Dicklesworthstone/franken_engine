//! Session-authenticated extension hostcall channel with per-message MAC.
//!
//! This module amortizes asymmetric authentication into a deterministic
//! handshake and then authenticates each hostcall envelope with a keyed MAC.
//! Each session is bound to `(session_id, extension_id, host_id)`, enforces
//! monotonic sequences, and provides authenticated backpressure signaling.
//!
//! Plan references: Section 10.10 item 14, 9E.6 (session-authenticated
//! hostcall channel).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::signature_preimage::{
    Signature, SignatureError, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// Session state / config
// ---------------------------------------------------------------------------

/// Session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Init,
    Established,
    Expired,
    Closed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => write!(f, "init"),
            Self::Established => write!(f, "established"),
            Self::Expired => write!(f, "expired"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Receiver-side sequence progression policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SequencePolicy {
    /// Require `received_seq == last_seen + 1`.
    Strict,
    /// Require only `received_seq > last_seen`.
    Monotonic,
}

impl fmt::Display for SequencePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Monotonic => write!(f, "monotonic"),
        }
    }
}

/// Session behavior limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Maximum wall-clock/virtual lifetime in ticks.
    pub max_lifetime_ticks: u64,
    /// Maximum total messages (send+receive) before forced re-handshake.
    pub max_messages: u64,
    /// Maximum queued inbound messages before backpressure.
    pub max_buffered_messages: usize,
    /// Sequence progression policy for replay/out-of-order handling.
    pub sequence_policy: SequencePolicy,
    /// Replay drop count threshold before escalation to session expiry.
    pub replay_drop_threshold: u64,
    /// Tick window used for replay-drop rate limiting.
    pub replay_drop_window_ticks: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_lifetime_ticks: 10_000,
            max_messages: 10_000,
            max_buffered_messages: 256,
            sequence_policy: SequencePolicy::Monotonic,
            replay_drop_threshold: 8,
            replay_drop_window_ticks: 1_000,
        }
    }
}

/// Handle returned to callers once a session is established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandle {
    pub session_id: String,
}

/// Input bundle for shared-buffer sends to keep API ergonomics clippy-clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSendInput<'a> {
    pub region_id: u64,
    pub payload: &'a [u8],
    pub trace_id: &'a str,
    pub timestamp_ticks: u64,
    pub decision_id: Option<&'a str>,
    pub policy_id: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Handshake transcript
// ---------------------------------------------------------------------------

/// Input used to build and verify a deterministic mutual-auth handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHandshake {
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub extension_nonce: u64,
    pub host_nonce: u64,
    pub timestamp_ticks: u64,
    pub trace_id: String,
}

/// Signed extension->host handshake request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub extension_nonce: u64,
    pub timestamp_ticks: u64,
    pub extension_key: VerificationKey,
    pub signature: Signature,
}

/// Signed host->extension handshake response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub session_id: String,
    pub extension_nonce: u64,
    pub host_nonce: u64,
    pub host_key: VerificationKey,
    pub signature: Signature,
}

// ---------------------------------------------------------------------------
// Envelope / payload types
// ---------------------------------------------------------------------------

/// Descriptor for shared-memory payload transport (zero-copy style).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedPayloadDescriptor {
    pub region_id: u64,
    pub payload_len: usize,
    pub payload_hash: ContentHash,
}

/// Authenticated backpressure signal payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureSignal {
    pub pending_messages: usize,
    pub limit: usize,
}

/// Payload carried by a hostcall envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelPayload {
    Inline(Vec<u8>),
    Shared(SharedPayloadDescriptor),
    Backpressure(BackpressureSignal),
}

/// Supported AEAD algorithms for data-plane envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    ChaCha20Poly1305,
    Aes256Gcm,
    XChaCha20Poly1305,
}

impl AeadAlgorithm {
    pub fn nonce_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 | Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    pub fn max_messages_per_key(self) -> u64 {
        match self {
            // Conservative cap from 96-bit nonce guidance.
            Self::Aes256Gcm => 1u64 << 32,
            // Treated as effectively unbounded within u64 session sequencing.
            Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305 => u64::MAX,
        }
    }

    #[allow(dead_code)]
    fn as_tag(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 1,
            Self::Aes256Gcm => 2,
            Self::XChaCha20Poly1305 => 3,
        }
    }
}

/// Direction discriminator for nonce derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataPlaneDirection {
    HostToExtension,
    ExtensionToHost,
}

impl DataPlaneDirection {
    #[allow(dead_code)]
    fn as_byte(self) -> u8 {
        match self {
            Self::HostToExtension => 0x00,
            Self::ExtensionToHost => 0x01,
        }
    }
}

/// Deterministically derived AEAD nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicNonce {
    bytes: Vec<u8>,
}

impl DeterministicNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Envelope authenticated per message with session MAC key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallEnvelope {
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub sequence: u64,
    pub payload: ChannelPayload,
    pub mac: AuthenticityHash,
    pub trace_id: String,
    pub sent_at_tick: u64,
}

// ---------------------------------------------------------------------------
// Errors / events
// ---------------------------------------------------------------------------

/// Errors from session channel operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionChannelError {
    InvalidIdentity {
        field: String,
    },
    InvalidHandshake {
        detail: String,
    },
    SignatureFailure(SignatureError),
    SessionAlreadyExists {
        session_id: String,
    },
    SessionNotFound {
        session_id: String,
    },
    SessionNotEstablished {
        session_id: String,
        state: SessionState,
    },
    SessionExpired {
        session_id: String,
        reason: String,
    },
    Backpressure {
        session_id: String,
        pending: usize,
        limit: usize,
    },
    NoMessageAvailable {
        session_id: String,
    },
    SessionBindingMismatch {
        expected_session_id: String,
        actual_session_id: String,
    },
    MacMismatch {
        session_id: String,
        sequence: u64,
    },
    InvalidControlSignal {
        session_id: String,
        detail: String,
    },
    ReplayDetected {
        session_id: String,
        sequence: u64,
        last_seen: u64,
    },
    OutOfOrderDetected {
        session_id: String,
        sequence: u64,
        expected_min: u64,
    },
    NonceExhausted {
        sequence: u64,
        limit: u64,
        algorithm: AeadAlgorithm,
    },
}

impl fmt::Display for SessionChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity { field } => write!(f, "invalid identity field: {field}"),
            Self::InvalidHandshake { detail } => write!(f, "invalid handshake: {detail}"),
            Self::SignatureFailure(err) => write!(f, "signature failure: {err}"),
            Self::SessionAlreadyExists { session_id } => {
                write!(f, "session already exists: {session_id}")
            }
            Self::SessionNotFound { session_id } => write!(f, "session not found: {session_id}"),
            Self::SessionNotEstablished { session_id, state } => {
                write!(f, "session {session_id} not established (state: {state})")
            }
            Self::SessionExpired { session_id, reason } => {
                write!(f, "session {session_id} expired: {reason}")
            }
            Self::Backpressure {
                session_id,
                pending,
                limit,
            } => write!(
                f,
                "session {session_id} backpressure: pending={pending}, limit={limit}"
            ),
            Self::NoMessageAvailable { session_id } => {
                write!(f, "no message available for session {session_id}")
            }
            Self::SessionBindingMismatch {
                expected_session_id,
                actual_session_id,
            } => write!(
                f,
                "session binding mismatch: expected {expected_session_id}, got {actual_session_id}"
            ),
            Self::MacMismatch {
                session_id,
                sequence,
            } => {
                write!(f, "MAC mismatch on {session_id} sequence {sequence}")
            }
            Self::InvalidControlSignal { session_id, detail } => {
                write!(f, "invalid control signal on {session_id}: {detail}")
            }
            Self::ReplayDetected {
                session_id,
                sequence,
                last_seen,
            } => write!(
                f,
                "replay detected on {session_id}: sequence={sequence}, last_seen={last_seen}"
            ),
            Self::OutOfOrderDetected {
                session_id,
                sequence,
                expected_min,
            } => write!(
                f,
                "out-of-order sequence on {session_id}: sequence={sequence}, expected_min={expected_min}"
            ),
            Self::NonceExhausted {
                sequence,
                limit,
                algorithm,
            } => write!(
                f,
                "nonce budget exhausted for {algorithm:?}: sequence={sequence}, limit={limit}"
            ),
        }
    }
}

impl std::error::Error for SessionChannelError {}

impl From<SignatureError> for SessionChannelError {
    fn from(value: SignatureError) -> Self {
        Self::SignatureFailure(value)
    }
}

/// Structured observability event for session channel operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChannelEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub session_id: String,
    pub extension_id: String,
    pub host_id: String,
    pub sequence: Option<u64>,
    pub expected_min_seq: Option<u64>,
    pub received_seq: Option<u64>,
    pub drop_reason: Option<String>,
    pub source_principal: Option<String>,
    pub timestamp_ticks: u64,
}

/// Replay/drop classification for sequence policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayDropReason {
    Replay,
    Duplicate,
    OutOfOrder,
}

impl ReplayDropReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Duplicate => "duplicate",
            Self::OutOfOrder => "out_of_order",
        }
    }
}

// ---------------------------------------------------------------------------
// SessionHostcallChannel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SessionRecord {
    session_id: String,
    extension_id: String,
    host_id: String,
    state: SessionState,
    session_key: [u8; 32],
    expires_at_tick: u64,
    max_messages: u64,
    sent_messages: u64,
    received_messages: u64,
    next_sequence: u64,
    last_received_sequence: u64,
    next_signal_sequence: u64,
    last_verified_signal_sequence: u64,
    sequence_policy: SequencePolicy,
    replay_drop_threshold: u64,
    replay_drop_window_ticks: u64,
    replay_drop_count_in_window: u64,
    replay_drop_window_start_tick: u64,
    max_buffered_messages: usize,
    inbound: VecDeque<HostcallEnvelope>,
}

/// Session-authenticated channel for extension hostcalls.
#[derive(Debug, Default)]
pub struct SessionHostcallChannel {
    sessions: BTreeMap<String, SessionRecord>,
    events: Vec<SessionChannelEvent>,
}

impl SessionHostcallChannel {
    /// Create an empty channel registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build, verify, and establish a new session using deterministic
    /// mutually-signed handshake transcript.
    pub fn create_session(
        &mut self,
        handshake: SessionHandshake,
        extension_signing_key: &SigningKey,
        host_signing_key: &SigningKey,
        config: SessionConfig,
    ) -> Result<SessionHandle, SessionChannelError> {
        validate_identity_field("session_id", &handshake.session_id)?;
        validate_identity_field("extension_id", &handshake.extension_id)?;
        validate_identity_field("host_id", &handshake.host_id)?;
        if handshake.extension_id == handshake.host_id {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "extension_id and host_id must differ".to_string(),
            });
        }
        if self.sessions.contains_key(&handshake.session_id) {
            return Err(SessionChannelError::SessionAlreadyExists {
                session_id: handshake.session_id,
            });
        }
        if config.max_messages == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "max_messages must be > 0".to_string(),
            });
        }
        if config.max_lifetime_ticks == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "max_lifetime_ticks must be > 0".to_string(),
            });
        }
        if config.max_buffered_messages == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "max_buffered_messages must be > 0".to_string(),
            });
        }
        if config.replay_drop_threshold > 0 && config.replay_drop_window_ticks == 0 {
            return Err(SessionChannelError::InvalidHandshake {
                detail: "replay_drop_window_ticks must be > 0 when replay_drop_threshold > 0"
                    .to_string(),
            });
        }

        let extension_key = extension_signing_key.verification_key();
        let host_key = host_signing_key.verification_key();

        let request_preimage = handshake_request_preimage(&handshake, &extension_key);
        let request_sig = sign_preimage(extension_signing_key, &request_preimage)?;
        verify_signature(&extension_key, &request_preimage, &request_sig)?;

        let request = HandshakeRequest {
            session_id: handshake.session_id.clone(),
            extension_id: handshake.extension_id.clone(),
            host_id: handshake.host_id.clone(),
            extension_nonce: handshake.extension_nonce,
            timestamp_ticks: handshake.timestamp_ticks,
            extension_key: extension_key.clone(),
            signature: request_sig.clone(),
        };

        let response_preimage =
            handshake_response_preimage(&request, handshake.host_nonce, &host_key);
        let response_sig = sign_preimage(host_signing_key, &response_preimage)?;
        verify_signature(&host_key, &response_preimage, &response_sig)?;

        let response = HandshakeResponse {
            session_id: handshake.session_id.clone(),
            extension_nonce: handshake.extension_nonce,
            host_nonce: handshake.host_nonce,
            host_key,
            signature: response_sig,
        };

        let session_key =
            derive_session_key(&request_preimage, &response_preimage, &request, &response);
        let expires_at_tick = handshake
            .timestamp_ticks
            .saturating_add(config.max_lifetime_ticks);

        self.sessions.insert(
            handshake.session_id.clone(),
            SessionRecord {
                session_id: handshake.session_id.clone(),
                extension_id: handshake.extension_id.clone(),
                host_id: handshake.host_id.clone(),
                state: SessionState::Established,
                session_key,
                expires_at_tick,
                max_messages: config.max_messages,
                sent_messages: 0,
                received_messages: 0,
                next_sequence: 1,
                last_received_sequence: 0,
                next_signal_sequence: 1,
                last_verified_signal_sequence: 0,
                sequence_policy: config.sequence_policy,
                replay_drop_threshold: config.replay_drop_threshold,
                replay_drop_window_ticks: config.replay_drop_window_ticks,
                replay_drop_count_in_window: 0,
                replay_drop_window_start_tick: handshake.timestamp_ticks,
                max_buffered_messages: config.max_buffered_messages,
                inbound: VecDeque::new(),
            },
        );

        self.emit_event(SessionEventInput {
            trace_id: handshake.trace_id,
            decision_id: None,
            policy_id: None,
            event: "session_created",
            outcome: "ok",
            error_code: None,
            session_id: handshake.session_id.clone(),
            extension_id: handshake.extension_id,
            host_id: handshake.host_id,
            sequence: None,
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks: handshake.timestamp_ticks,
        });

        Ok(SessionHandle {
            session_id: handshake.session_id,
        })
    }

    /// Send an inline payload on an established session.
    pub fn send(
        &mut self,
        handle: &SessionHandle,
        payload: Vec<u8>,
        trace_id: &str,
        timestamp_ticks: u64,
        decision_id: Option<&str>,
        policy_id: Option<&str>,
    ) -> Result<u64, SessionChannelError> {
        let (sequence, session_id, extension_id, host_id) = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            ensure_session_active(session, timestamp_ticks)?;

            if session.inbound.len() >= session.max_buffered_messages {
                return Err(SessionChannelError::Backpressure {
                    session_id: session.session_id.clone(),
                    pending: session.inbound.len(),
                    limit: session.max_buffered_messages,
                });
            }

            if session.next_sequence == u64::MAX {
                session.state = SessionState::Expired;
                return Err(SessionChannelError::SessionExpired {
                    session_id: session.session_id.clone(),
                    reason: "sequence_exhausted".to_string(),
                });
            }

            let sequence = session.next_sequence;
            let mut envelope = HostcallEnvelope {
                session_id: session.session_id.clone(),
                extension_id: session.extension_id.clone(),
                host_id: session.host_id.clone(),
                sequence,
                payload: ChannelPayload::Inline(payload),
                mac: AuthenticityHash([0u8; 32]),
                trace_id: trace_id.to_string(),
                sent_at_tick: timestamp_ticks,
            };
            envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
            session.inbound.push_back(envelope);
            session.next_sequence += 1;
            session.sent_messages = session.sent_messages.saturating_add(1);
            (
                sequence,
                session.session_id.clone(),
                session.extension_id.clone(),
                session.host_id.clone(),
            )
        };

        self.emit_event(SessionEventInput {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.map(ToOwned::to_owned),
            policy_id: policy_id.map(ToOwned::to_owned),
            event: "message_sent",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: Some(sequence),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks,
        });

        Ok(sequence)
    }

    /// Send a shared-memory descriptor payload without copying message bytes.
    pub fn send_shared_buffer(
        &mut self,
        handle: &SessionHandle,
        input: SharedSendInput<'_>,
    ) -> Result<u64, SessionChannelError> {
        let descriptor = SharedPayloadDescriptor {
            region_id: input.region_id,
            payload_len: input.payload.len(),
            payload_hash: ContentHash::compute(input.payload),
        };

        let (sequence, session_id, extension_id, host_id) = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            ensure_session_active(session, input.timestamp_ticks)?;

            if session.inbound.len() >= session.max_buffered_messages {
                return Err(SessionChannelError::Backpressure {
                    session_id: session.session_id.clone(),
                    pending: session.inbound.len(),
                    limit: session.max_buffered_messages,
                });
            }

            if session.next_sequence == u64::MAX {
                session.state = SessionState::Expired;
                return Err(SessionChannelError::SessionExpired {
                    session_id: session.session_id.clone(),
                    reason: "sequence_exhausted".to_string(),
                });
            }

            let sequence = session.next_sequence;
            let mut envelope = HostcallEnvelope {
                session_id: session.session_id.clone(),
                extension_id: session.extension_id.clone(),
                host_id: session.host_id.clone(),
                sequence,
                payload: ChannelPayload::Shared(descriptor),
                mac: AuthenticityHash([0u8; 32]),
                trace_id: input.trace_id.to_string(),
                sent_at_tick: input.timestamp_ticks,
            };
            envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
            session.inbound.push_back(envelope);
            session.next_sequence += 1;
            session.sent_messages = session.sent_messages.saturating_add(1);
            (
                sequence,
                session.session_id.clone(),
                session.extension_id.clone(),
                session.host_id.clone(),
            )
        };

        self.emit_event(SessionEventInput {
            trace_id: input.trace_id.to_string(),
            decision_id: input.decision_id.map(ToOwned::to_owned),
            policy_id: input.policy_id.map(ToOwned::to_owned),
            event: "shared_payload_sent",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: Some(sequence),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks: input.timestamp_ticks,
        });

        Ok(sequence)
    }

    /// Receive and verify the next queued envelope for a session.
    pub fn receive(
        &mut self,
        handle: &SessionHandle,
        trace_id: &str,
        timestamp_ticks: u64,
        decision_id: Option<&str>,
        policy_id: Option<&str>,
    ) -> Result<ChannelPayload, SessionChannelError> {
        let mut drop_event: Option<SessionEventInput> = None;
        let mut escalation_event: Option<SessionEventInput> = None;

        let receive_result = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            ensure_session_active(session, timestamp_ticks)?;

            let envelope = session.inbound.pop_front().ok_or_else(|| {
                SessionChannelError::NoMessageAvailable {
                    session_id: session.session_id.clone(),
                }
            })?;

            if envelope.session_id != session.session_id {
                return Err(SessionChannelError::SessionBindingMismatch {
                    expected_session_id: session.session_id.clone(),
                    actual_session_id: envelope.session_id,
                });
            }
            if envelope.extension_id != session.extension_id || envelope.host_id != session.host_id
            {
                return Err(SessionChannelError::SessionBindingMismatch {
                    expected_session_id: session.session_id.clone(),
                    actual_session_id: envelope.session_id,
                });
            }

            let expected_mac = compute_envelope_mac(&session.session_key, &envelope);
            if !expected_mac.constant_time_eq(&envelope.mac) {
                return Err(SessionChannelError::MacMismatch {
                    session_id: session.session_id.clone(),
                    sequence: envelope.sequence,
                });
            }

            let expected_min_seq = session.last_received_sequence.saturating_add(1);
            let drop_reason = if envelope.sequence == session.last_received_sequence {
                Some(ReplayDropReason::Duplicate)
            } else if envelope.sequence < session.last_received_sequence {
                Some(ReplayDropReason::Replay)
            } else if session.sequence_policy == SequencePolicy::Strict
                && envelope.sequence != expected_min_seq
            {
                Some(ReplayDropReason::OutOfOrder)
            } else {
                None
            };

            if let Some(reason) = drop_reason {
                let source_principal = envelope.extension_id.clone();
                let error = match reason {
                    ReplayDropReason::OutOfOrder => SessionChannelError::OutOfOrderDetected {
                        session_id: session.session_id.clone(),
                        sequence: envelope.sequence,
                        expected_min: expected_min_seq,
                    },
                    ReplayDropReason::Replay | ReplayDropReason::Duplicate => {
                        SessionChannelError::ReplayDetected {
                            session_id: session.session_id.clone(),
                            sequence: envelope.sequence,
                            last_seen: session.last_received_sequence,
                        }
                    }
                };

                let error_code = match reason {
                    ReplayDropReason::Replay => "FE-5003",
                    ReplayDropReason::Duplicate => "FE-5004",
                    ReplayDropReason::OutOfOrder => "FE-5005",
                };

                drop_event = Some(SessionEventInput {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.map(ToOwned::to_owned),
                    policy_id: policy_id.map(ToOwned::to_owned),
                    event: "message_dropped",
                    outcome: "drop",
                    error_code: Some(error_code),
                    session_id: session.session_id.clone(),
                    extension_id: session.extension_id.clone(),
                    host_id: session.host_id.clone(),
                    sequence: Some(envelope.sequence),
                    expected_min_seq: Some(expected_min_seq),
                    received_seq: Some(envelope.sequence),
                    drop_reason: Some(reason.as_str()),
                    source_principal: Some(source_principal.clone()),
                    timestamp_ticks,
                });

                if register_replay_drop(session, timestamp_ticks) {
                    session.state = SessionState::Expired;
                    escalation_event = Some(SessionEventInput {
                        trace_id: trace_id.to_string(),
                        decision_id: decision_id.map(ToOwned::to_owned),
                        policy_id: policy_id.map(ToOwned::to_owned),
                        event: "replay_drop_threshold_exceeded",
                        outcome: "escalated",
                        error_code: Some("FE-5009"),
                        session_id: session.session_id.clone(),
                        extension_id: session.extension_id.clone(),
                        host_id: session.host_id.clone(),
                        sequence: Some(envelope.sequence),
                        expected_min_seq: Some(expected_min_seq),
                        received_seq: Some(envelope.sequence),
                        drop_reason: Some(reason.as_str()),
                        source_principal: Some(source_principal),
                        timestamp_ticks,
                    });
                    Err(SessionChannelError::SessionExpired {
                        session_id: session.session_id.clone(),
                        reason: "replay_drop_threshold_exceeded".to_string(),
                    })
                } else {
                    Err(error)
                }
            } else {
                session.last_received_sequence = envelope.sequence;
                session.received_messages = session.received_messages.saturating_add(1);
                Ok((
                    envelope.payload,
                    session.session_id.clone(),
                    session.extension_id.clone(),
                    session.host_id.clone(),
                    envelope.sequence,
                ))
            }
        };

        if let Some(event) = drop_event {
            self.emit_event(event);
        }
        if let Some(event) = escalation_event {
            self.emit_event(event);
        }

        let (payload, session_id, extension_id, host_id, sequence) = receive_result?;

        self.emit_event(SessionEventInput {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.map(ToOwned::to_owned),
            policy_id: policy_id.map(ToOwned::to_owned),
            event: "message_received",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: Some(sequence),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks,
        });

        Ok(payload)
    }

    /// Close an active session.
    pub fn close_session(
        &mut self,
        handle: &SessionHandle,
        trace_id: &str,
        timestamp_ticks: u64,
        decision_id: Option<&str>,
        policy_id: Option<&str>,
    ) -> Result<(), SessionChannelError> {
        let (session_id, extension_id, host_id) = {
            let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
                SessionChannelError::SessionNotFound {
                    session_id: handle.session_id.clone(),
                }
            })?;
            if session.state == SessionState::Closed {
                return Err(SessionChannelError::SessionNotEstablished {
                    session_id: session.session_id.clone(),
                    state: session.state,
                });
            }
            session.state = SessionState::Closed;
            (
                session.session_id.clone(),
                session.extension_id.clone(),
                session.host_id.clone(),
            )
        };

        self.emit_event(SessionEventInput {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.map(ToOwned::to_owned),
            policy_id: policy_id.map(ToOwned::to_owned),
            event: "session_closed",
            outcome: "ok",
            error_code: None,
            session_id,
            extension_id,
            host_id,
            sequence: None,
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks,
        });

        Ok(())
    }

    /// Create an authenticated backpressure signal envelope.
    pub fn authenticated_backpressure_signal(
        &mut self,
        handle: &SessionHandle,
        pending_messages: usize,
        limit: usize,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> Result<HostcallEnvelope, SessionChannelError> {
        let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
            SessionChannelError::SessionNotFound {
                session_id: handle.session_id.clone(),
            }
        })?;
        ensure_session_active(session, timestamp_ticks)?;
        if session.next_signal_sequence == u64::MAX {
            session.state = SessionState::Expired;
            return Err(SessionChannelError::SessionExpired {
                session_id: session.session_id.clone(),
                reason: "signal_sequence_exhausted".to_string(),
            });
        }

        let sequence = session.next_signal_sequence;
        session.next_signal_sequence += 1;
        session.sent_messages = session.sent_messages.saturating_add(1);

        let mut envelope = HostcallEnvelope {
            session_id: session.session_id.clone(),
            extension_id: session.extension_id.clone(),
            host_id: session.host_id.clone(),
            sequence,
            payload: ChannelPayload::Backpressure(BackpressureSignal {
                pending_messages,
                limit,
            }),
            mac: AuthenticityHash([0u8; 32]),
            trace_id: trace_id.to_string(),
            sent_at_tick: timestamp_ticks,
        };
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        Ok(envelope)
    }

    /// Verify an authenticated control/backpressure signal.
    pub fn verify_authenticated_signal(
        &mut self,
        handle: &SessionHandle,
        envelope: &HostcallEnvelope,
    ) -> Result<(), SessionChannelError> {
        let session = self.sessions.get_mut(&handle.session_id).ok_or_else(|| {
            SessionChannelError::SessionNotFound {
                session_id: handle.session_id.clone(),
            }
        })?;
        if session.state != SessionState::Established {
            return Err(SessionChannelError::SessionNotEstablished {
                session_id: session.session_id.clone(),
                state: session.state,
            });
        }
        if envelope.session_id != session.session_id {
            return Err(SessionChannelError::SessionBindingMismatch {
                expected_session_id: session.session_id.clone(),
                actual_session_id: envelope.session_id.clone(),
            });
        }
        if envelope.extension_id != session.extension_id || envelope.host_id != session.host_id {
            return Err(SessionChannelError::SessionBindingMismatch {
                expected_session_id: session.session_id.clone(),
                actual_session_id: envelope.session_id.clone(),
            });
        }
        if !matches!(envelope.payload, ChannelPayload::Backpressure(_)) {
            return Err(SessionChannelError::InvalidControlSignal {
                session_id: session.session_id.clone(),
                detail: "expected backpressure control payload".to_string(),
            });
        }
        let expected = compute_envelope_mac(&session.session_key, envelope);
        if !expected.constant_time_eq(&envelope.mac) {
            return Err(SessionChannelError::MacMismatch {
                session_id: session.session_id.clone(),
                sequence: envelope.sequence,
            });
        }

        let expected_min_seq = session.last_verified_signal_sequence.saturating_add(1);
        let replay_reason = if envelope.sequence == session.last_verified_signal_sequence {
            Some(ReplayDropReason::Duplicate)
        } else if envelope.sequence < session.last_verified_signal_sequence {
            Some(ReplayDropReason::Replay)
        } else if session.sequence_policy == SequencePolicy::Strict
            && envelope.sequence != expected_min_seq
        {
            Some(ReplayDropReason::OutOfOrder)
        } else {
            None
        };

        if let Some(reason) = replay_reason {
            if register_replay_drop(session, envelope.sent_at_tick) {
                session.state = SessionState::Expired;
                return Err(SessionChannelError::SessionExpired {
                    session_id: session.session_id.clone(),
                    reason: "control_signal_replay_drop_threshold_exceeded".to_string(),
                });
            }
            return match reason {
                ReplayDropReason::OutOfOrder => Err(SessionChannelError::OutOfOrderDetected {
                    session_id: session.session_id.clone(),
                    sequence: envelope.sequence,
                    expected_min: expected_min_seq,
                }),
                ReplayDropReason::Replay | ReplayDropReason::Duplicate => {
                    Err(SessionChannelError::ReplayDetected {
                        session_id: session.session_id.clone(),
                        sequence: envelope.sequence,
                        last_seen: session.last_verified_signal_sequence,
                    })
                }
            };
        }

        session.last_verified_signal_sequence = envelope.sequence;
        session.received_messages = session.received_messages.saturating_add(1);
        Ok(())
    }

    /// Current queue length for a session.
    pub fn queue_len(&self, handle: &SessionHandle) -> Option<usize> {
        self.sessions
            .get(&handle.session_id)
            .map(|s| s.inbound.len())
    }

    /// Session state for a handle.
    pub fn session_state(&self, handle: &SessionHandle) -> Option<SessionState> {
        self.sessions.get(&handle.session_id).map(|s| s.state)
    }

    /// Drain accumulated structured events.
    pub fn drain_events(&mut self) -> Vec<SessionChannelEvent> {
        std::mem::take(&mut self.events)
    }

    fn emit_event(&mut self, input: SessionEventInput) {
        self.events.push(SessionChannelEvent {
            trace_id: input.trace_id,
            decision_id: input.decision_id,
            policy_id: input.policy_id,
            component: "session_hostcall_channel".to_string(),
            event: input.event.to_string(),
            outcome: input.outcome.to_string(),
            error_code: input.error_code.map(ToOwned::to_owned),
            session_id: input.session_id,
            extension_id: input.extension_id,
            host_id: input.host_id,
            sequence: input.sequence,
            expected_min_seq: input.expected_min_seq,
            received_seq: input.received_seq,
            drop_reason: input.drop_reason.map(ToOwned::to_owned),
            source_principal: input.source_principal,
            timestamp_ticks: input.timestamp_ticks,
        });
    }
}

/// Deterministically derive an AEAD nonce from session key + direction + sequence.
///
/// This is the only supported nonce construction path for session data-plane
/// envelopes; ad-hoc/random nonces are intentionally not exposed.
pub fn derive_deterministic_aead_nonce(
    session_key: &[u8; 32],
    direction: DataPlaneDirection,
    sequence: u64,
    algorithm: AeadAlgorithm,
) -> Result<DeterministicNonce, SessionChannelError> {
    enforce_nonce_budget(sequence, algorithm)?;

    let mut info = Vec::new();
    info.extend_from_slice(b"fe::hostcall::aead-nonce");
    info.push(direction.as_byte());
    info.push(algorithm.as_tag());
    info.extend_from_slice(&sequence.to_be_bytes());

    Ok(DeterministicNonce {
        bytes: hkdf_expand(session_key, &info, algorithm.nonce_len()),
    })
}

/// Build deterministic AEAD associated-data bytes for context binding.
pub fn build_aead_associated_data(session_id: &str, message_type: &str, flags: u32) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(b"fe::hostcall::aead-ad");
    append_str(&mut ad, session_id);
    append_str(&mut ad, message_type);
    ad.extend_from_slice(&flags.to_be_bytes());
    ad
}

fn enforce_nonce_budget(
    sequence: u64,
    algorithm: AeadAlgorithm,
) -> Result<(), SessionChannelError> {
    let limit = algorithm.max_messages_per_key();
    if sequence >= limit {
        return Err(SessionChannelError::NonceExhausted {
            sequence,
            limit,
            algorithm,
        });
    }
    Ok(())
}

#[derive(Debug)]
struct SessionEventInput {
    trace_id: String,
    decision_id: Option<String>,
    policy_id: Option<String>,
    event: &'static str,
    outcome: &'static str,
    error_code: Option<&'static str>,
    session_id: String,
    extension_id: String,
    host_id: String,
    sequence: Option<u64>,
    expected_min_seq: Option<u64>,
    received_seq: Option<u64>,
    drop_reason: Option<&'static str>,
    source_principal: Option<String>,
    timestamp_ticks: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_identity_field(field: &str, value: &str) -> Result<(), SessionChannelError> {
    if value.is_empty() {
        return Err(SessionChannelError::InvalidIdentity {
            field: field.to_string(),
        });
    }
    if value.len() > 128 {
        return Err(SessionChannelError::InvalidIdentity {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn ensure_session_active(
    session: &mut SessionRecord,
    now_ticks: u64,
) -> Result<(), SessionChannelError> {
    if session.state != SessionState::Established {
        return Err(SessionChannelError::SessionNotEstablished {
            session_id: session.session_id.clone(),
            state: session.state,
        });
    }
    if now_ticks >= session.expires_at_tick {
        session.state = SessionState::Expired;
        return Err(SessionChannelError::SessionExpired {
            session_id: session.session_id.clone(),
            reason: "lifetime_exceeded".to_string(),
        });
    }
    if session
        .sent_messages
        .saturating_add(session.received_messages)
        >= session.max_messages
    {
        session.state = SessionState::Expired;
        return Err(SessionChannelError::SessionExpired {
            session_id: session.session_id.clone(),
            reason: "message_budget_exceeded".to_string(),
        });
    }
    Ok(())
}

fn register_replay_drop(session: &mut SessionRecord, now_ticks: u64) -> bool {
    if session.replay_drop_threshold == 0 || session.replay_drop_window_ticks == 0 {
        return false;
    }

    let elapsed = now_ticks.saturating_sub(session.replay_drop_window_start_tick);
    if elapsed >= session.replay_drop_window_ticks {
        session.replay_drop_window_start_tick = now_ticks;
        session.replay_drop_count_in_window = 0;
    }

    session.replay_drop_count_in_window = session.replay_drop_count_in_window.saturating_add(1);
    session.replay_drop_count_in_window > session.replay_drop_threshold
}

fn handshake_request_preimage(
    handshake: &SessionHandshake,
    extension_key: &VerificationKey,
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"fe::hostcall::handshake::request");
    append_str(&mut preimage, &handshake.session_id);
    append_str(&mut preimage, &handshake.extension_id);
    append_str(&mut preimage, &handshake.host_id);
    preimage.extend_from_slice(&handshake.extension_nonce.to_be_bytes());
    preimage.extend_from_slice(&handshake.timestamp_ticks.to_be_bytes());
    preimage.extend_from_slice(extension_key.as_bytes());
    preimage
}

fn handshake_response_preimage(
    request: &HandshakeRequest,
    host_nonce: u64,
    host_key: &VerificationKey,
) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"fe::hostcall::handshake::response");
    append_str(&mut preimage, &request.session_id);
    append_str(&mut preimage, &request.extension_id);
    append_str(&mut preimage, &request.host_id);
    preimage.extend_from_slice(&request.extension_nonce.to_be_bytes());
    preimage.extend_from_slice(&host_nonce.to_be_bytes());
    preimage.extend_from_slice(host_key.as_bytes());
    preimage.extend_from_slice(&request.signature.to_bytes());
    preimage
}

fn derive_session_key(
    request_preimage: &[u8],
    response_preimage: &[u8],
    request: &HandshakeRequest,
    response: &HandshakeResponse,
) -> [u8; 32] {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(request_preimage);
    transcript.extend_from_slice(&request.signature.to_bytes());
    transcript.extend_from_slice(response_preimage);
    transcript.extend_from_slice(&response.signature.to_bytes());

    let transcript_hash = ContentHash::compute(&transcript);

    // HKDF-Extract input keying material: authenticated transcript artifacts.
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&request.signature.to_bytes());
    ikm.extend_from_slice(&response.signature.to_bytes());
    ikm.extend_from_slice(request.extension_key.as_bytes());
    ikm.extend_from_slice(response.host_key.as_bytes());
    ikm.extend_from_slice(request_preimage);
    ikm.extend_from_slice(response_preimage);

    // Context-bound salt couples identity/session/timing/nonce fields.
    let mut salt = Vec::new();
    salt.extend_from_slice(b"fe::hostcall::hkdf::salt");
    append_str(&mut salt, &request.session_id);
    append_str(&mut salt, &request.extension_id);
    append_str(&mut salt, &request.host_id);
    salt.extend_from_slice(&request.timestamp_ticks.to_be_bytes());
    salt.extend_from_slice(&request.extension_nonce.to_be_bytes());
    salt.extend_from_slice(&response.host_nonce.to_be_bytes());
    salt.extend_from_slice(transcript_hash.as_bytes());
    let prk = hkdf_extract(&salt, &ikm);

    // HKDF-Expand info is domain-separated and includes transcript hash.
    let mut info = Vec::new();
    info.extend_from_slice(b"fe::hostcall::hkdf::session-mac-key");
    append_str(&mut info, &request.session_id);
    append_str(&mut info, &request.extension_id);
    append_str(&mut info, &request.host_id);
    info.extend_from_slice(&request.timestamp_ticks.to_be_bytes());
    info.extend_from_slice(&request.extension_nonce.to_be_bytes());
    info.extend_from_slice(&response.host_nonce.to_be_bytes());
    info.extend_from_slice(transcript_hash.as_bytes());

    hkdf_expand_32(&prk, &info)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    // Tier-3 keyed hash acts as the HMAC primitive for extract.
    AuthenticityHash::compute_keyed(salt, ikm).0
}

fn hkdf_expand_32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let okm = hkdf_expand(prk, info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    if out_len == 0 {
        return Vec::new();
    }

    let mut okm = Vec::with_capacity(out_len);
    let mut previous_block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;

    while okm.len() < out_len {
        let mut block_input = Vec::with_capacity(previous_block.len() + info.len() + 1);
        if !previous_block.is_empty() {
            block_input.extend_from_slice(&previous_block);
        }
        block_input.extend_from_slice(info);
        block_input.push(counter);

        let block = AuthenticityHash::compute_keyed(prk, &block_input);
        previous_block = block.0.to_vec();
        okm.extend_from_slice(&previous_block);

        if counter == u8::MAX {
            break;
        }
        counter = counter.saturating_add(1);
    }

    okm.truncate(out_len);
    okm
}

fn compute_envelope_mac(session_key: &[u8; 32], envelope: &HostcallEnvelope) -> AuthenticityHash {
    let mut preimage = Vec::new();
    append_str(&mut preimage, &envelope.session_id);
    append_str(&mut preimage, &envelope.extension_id);
    append_str(&mut preimage, &envelope.host_id);
    preimage.extend_from_slice(&envelope.sequence.to_be_bytes());
    preimage.extend_from_slice(&envelope.sent_at_tick.to_be_bytes());
    append_str(&mut preimage, &envelope.trace_id);
    append_payload(&mut preimage, &envelope.payload);
    AuthenticityHash::compute_keyed(session_key, &preimage)
}

fn append_payload(preimage: &mut Vec<u8>, payload: &ChannelPayload) {
    match payload {
        ChannelPayload::Inline(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            preimage.extend_from_slice(bytes);
        }
        ChannelPayload::Shared(descriptor) => {
            preimage.push(2);
            preimage.extend_from_slice(&descriptor.region_id.to_be_bytes());
            preimage.extend_from_slice(&(descriptor.payload_len as u64).to_be_bytes());
            preimage.extend_from_slice(descriptor.payload_hash.as_bytes());
        }
        ChannelPayload::Backpressure(signal) => {
            preimage.push(3);
            preimage.extend_from_slice(&(signal.pending_messages as u64).to_be_bytes());
            preimage.extend_from_slice(&(signal.limit as u64).to_be_bytes());
        }
    }
}

fn append_str(preimage: &mut Vec<u8>, value: &str) {
    preimage.extend_from_slice(&(value.len() as u32).to_be_bytes());
    preimage.extend_from_slice(value.as_bytes());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes([byte; 32]).expect("serde deserialization should succeed")
    }

    fn handshake(session_id: &str, trace_id: &str, tick: u64) -> SessionHandshake {
        SessionHandshake {
            session_id: session_id.to_string(),
            extension_id: "extension-a".to_string(),
            host_id: "host-a".to_string(),
            extension_nonce: 7,
            host_nonce: 11,
            timestamp_ticks: tick,
            trace_id: trace_id.to_string(),
        }
    }

    fn create_basic_session(
        channel: &mut SessionHostcallChannel,
        session_id: &str,
    ) -> SessionHandle {
        create_session_with_config(channel, session_id, SessionConfig::default())
    }

    fn create_session_with_config(
        channel: &mut SessionHostcallChannel,
        session_id: &str,
        config: SessionConfig,
    ) -> SessionHandle {
        channel
            .create_session(
                handshake(session_id, "trace-create", 100),
                &signing_key(1),
                &signing_key(2),
                config,
            )
            .expect("session should be created")
    }

    #[test]
    fn create_session_performs_mutual_signature_handshake() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-1");
        assert_eq!(handle.session_id, "sess-1");
        assert_eq!(
            channel.session_state(&handle),
            Some(SessionState::Established)
        );

        let events = channel.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "session_created");
        assert_eq!(events[0].trace_id, "trace-create");
    }

    #[test]
    fn send_and_receive_round_trip_with_mac_verification() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-2");
        let seq = channel
            .send(
                &handle,
                b"hello".to_vec(),
                "trace-send",
                101,
                Some("dec-1"),
                Some("policy-1"),
            )
            .expect("send should pass");
        assert_eq!(seq, 1);

        let payload = channel
            .receive(&handle, "trace-recv", 102, Some("dec-2"), Some("policy-1"))
            .expect("receive should pass");
        assert_eq!(payload, ChannelPayload::Inline(b"hello".to_vec()));
        assert_eq!(channel.queue_len(&handle), Some(0));
    }

    #[test]
    fn tampered_payload_fails_mac_verification() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-3");
        channel
            .send(&handle, b"hello".to_vec(), "trace-send", 101, None, None)
            .expect("send should pass");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let envelope = session.inbound.front_mut().expect("envelope exists");
        envelope.payload = ChannelPayload::Inline(b"tampered".to_vec());

        let err = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::MacMismatch { .. }));
    }

    #[test]
    fn tampered_sequence_fails_mac_verification() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-seq-mac");
        channel
            .send(&handle, b"hello".to_vec(), "trace-send", 101, None, None)
            .expect("send should pass");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let envelope = session.inbound.front_mut().expect("envelope exists");
        envelope.sequence = 99;

        let err = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::MacMismatch { .. }));
    }

    #[test]
    fn replayed_sequence_is_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-4");
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send should pass");

        let replay_envelope = {
            let session = channel
                .sessions
                .get(&handle.session_id)
                .expect("session exists");
            session.inbound.front().cloned().expect("envelope exists")
        };

        let first = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive should pass");
        assert_eq!(first, ChannelPayload::Inline(b"first".to_vec()));

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        session.inbound.push_back(replay_envelope);

        let err = channel
            .receive(&handle, "trace-recv-2", 103, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));
    }

    #[test]
    fn lower_sequence_is_rejected_as_replay() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-lower");
        channel
            .send(&handle, b"first".to_vec(), "trace-send-1", 101, None, None)
            .expect("first send");
        let _ = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive");

        channel
            .send(&handle, b"second".to_vec(), "trace-send-2", 103, None, None)
            .expect("second send");
        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let mut envelope = session.inbound.pop_front().expect("envelope exists");
        envelope.sequence = 0;
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        session.inbound.push_front(envelope);

        let err = channel
            .receive(&handle, "trace-recv-2", 104, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));
    }

    #[test]
    fn strict_policy_rejects_sequence_gaps() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_session_with_config(
            &mut channel,
            "sess-strict",
            SessionConfig {
                sequence_policy: SequencePolicy::Strict,
                ..SessionConfig::default()
            },
        );
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let mut envelope = session.inbound.pop_front().expect("envelope exists");
        envelope.sequence = 3;
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        session.inbound.push_front(envelope);

        let err = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::OutOfOrderDetected { .. }
        ));
    }

    #[test]
    fn monotonic_policy_accepts_sequence_gaps() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_session_with_config(
            &mut channel,
            "sess-monotonic",
            SessionConfig {
                sequence_policy: SequencePolicy::Monotonic,
                ..SessionConfig::default()
            },
        );
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        let mut envelope = session.inbound.pop_front().expect("envelope exists");
        envelope.sequence = 3;
        envelope.mac = compute_envelope_mac(&session.session_key, &envelope);
        session.inbound.push_front(envelope);

        let payload = channel
            .receive(&handle, "trace-recv", 102, None, None)
            .expect("gap should be accepted in monotonic mode");
        assert_eq!(payload, ChannelPayload::Inline(b"first".to_vec()));
    }

    #[test]
    fn replay_drop_emits_structured_telemetry() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-telemetry");
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let replay = {
            let session = channel
                .sessions
                .get(&handle.session_id)
                .expect("session exists");
            session.inbound.front().cloned().expect("envelope exists")
        };

        let _ = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive");
        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        session.inbound.push_back(replay);

        let err = channel
            .receive(&handle, "trace-recv-2", 103, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));

        let events = channel.drain_events();
        let dropped = events
            .iter()
            .find(|event| event.event == "message_dropped")
            .expect("drop event present");
        assert_eq!(dropped.expected_min_seq, Some(2));
        assert_eq!(dropped.received_seq, Some(1));
        assert_eq!(dropped.drop_reason.as_deref(), Some("duplicate"));
        assert_eq!(dropped.source_principal.as_deref(), Some("extension-a"));
    }

    #[test]
    fn replay_drop_rate_limit_escalates_session() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_session_with_config(
            &mut channel,
            "sess-drop-limit",
            SessionConfig {
                replay_drop_threshold: 1,
                replay_drop_window_ticks: 100,
                ..SessionConfig::default()
            },
        );
        channel
            .send(&handle, b"first".to_vec(), "trace-send", 101, None, None)
            .expect("send");

        let replay = {
            let session = channel
                .sessions
                .get(&handle.session_id)
                .expect("session exists");
            session.inbound.front().cloned().expect("envelope exists")
        };

        let _ = channel
            .receive(&handle, "trace-recv-1", 102, None, None)
            .expect("first receive");

        {
            let session = channel
                .sessions
                .get_mut(&handle.session_id)
                .expect("session exists");
            session.inbound.push_back(replay.clone());
        }
        let first_drop = channel
            .receive(&handle, "trace-recv-2", 103, None, None)
            .unwrap_err();
        assert!(matches!(
            first_drop,
            SessionChannelError::ReplayDetected { .. }
        ));

        {
            let session = channel
                .sessions
                .get_mut(&handle.session_id)
                .expect("session exists");
            session.inbound.push_back(replay);
        }
        let second_drop = channel
            .receive(&handle, "trace-recv-3", 104, None, None)
            .unwrap_err();
        assert!(matches!(
            second_drop,
            SessionChannelError::SessionExpired { .. }
        ));
        assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));
    }

    #[test]
    fn sender_sequence_exhaustion_expires_session() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-seq-exhaust");
        let session = channel
            .sessions
            .get_mut(&handle.session_id)
            .expect("session exists");
        session.next_sequence = u64::MAX;

        let err = channel
            .send(&handle, b"x".to_vec(), "trace-send", 101, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::SessionExpired { .. }));
        assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));
    }

    #[test]
    fn session_binding_mismatch_rejects_cross_session_envelope() {
        let mut channel = SessionHostcallChannel::new();
        let handle_a = create_basic_session(&mut channel, "sess-a");
        let handle_b = create_basic_session(&mut channel, "sess-b");

        channel
            .send(&handle_a, b"a".to_vec(), "trace-a", 101, None, None)
            .expect("send a");

        let stolen = {
            let session_a = channel
                .sessions
                .get_mut(&handle_a.session_id)
                .expect("a exists");
            session_a.inbound.pop_front().expect("envelope exists")
        };
        let session_b = channel
            .sessions
            .get_mut(&handle_b.session_id)
            .expect("b exists");
        session_b.inbound.push_back(stolen);

        let err = channel
            .receive(&handle_b, "trace-b", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionBindingMismatch { .. }
        ));
    }

    #[test]
    fn session_expires_on_message_budget_and_lifetime() {
        let mut channel = SessionHostcallChannel::new();
        let handle = channel
            .create_session(
                handshake("sess-expire", "trace-expire", 100),
                &signing_key(3),
                &signing_key(4),
                SessionConfig {
                    max_lifetime_ticks: 2,
                    max_messages: 1,
                    max_buffered_messages: 2,
                    ..SessionConfig::default()
                },
            )
            .expect("session create");

        channel
            .send(&handle, b"one".to_vec(), "trace-send", 101, None, None)
            .expect("first send");
        let err_budget = channel
            .send(&handle, b"two".to_vec(), "trace-send-2", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err_budget,
            SessionChannelError::SessionExpired { .. }
        ));

        let handle2 = channel
            .create_session(
                handshake("sess-expire-2", "trace-expire-2", 100),
                &signing_key(5),
                &signing_key(6),
                SessionConfig {
                    max_lifetime_ticks: 1,
                    max_messages: 10,
                    max_buffered_messages: 2,
                    ..SessionConfig::default()
                },
            )
            .expect("session create");
        let err_lifetime = channel
            .send(&handle2, b"x".to_vec(), "trace-lifetime", 102, None, None)
            .unwrap_err();
        assert!(matches!(
            err_lifetime,
            SessionChannelError::SessionExpired { .. }
        ));
    }

    #[test]
    fn backpressure_limit_enforced_and_signal_is_authenticated() {
        let mut channel = SessionHostcallChannel::new();
        let handle = channel
            .create_session(
                handshake("sess-backpressure", "trace-backpressure", 100),
                &signing_key(7),
                &signing_key(8),
                SessionConfig {
                    max_lifetime_ticks: 100,
                    max_messages: 100,
                    max_buffered_messages: 1,
                    ..SessionConfig::default()
                },
            )
            .expect("session create");

        channel
            .send(&handle, b"one".to_vec(), "trace-send", 101, None, None)
            .expect("first send");
        let err = channel
            .send(&handle, b"two".to_vec(), "trace-send", 102, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::Backpressure { .. }));

        let mut signal = channel
            .authenticated_backpressure_signal(&handle, 1, 1, "trace-signal", 103)
            .expect("signal");
        channel
            .verify_authenticated_signal(&handle, &signal)
            .expect("auth should pass");

        signal.payload = ChannelPayload::Backpressure(BackpressureSignal {
            pending_messages: 999,
            limit: 1,
        });
        let err = channel
            .verify_authenticated_signal(&handle, &signal)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::MacMismatch { .. }));
    }

    #[test]
    fn shared_buffer_path_stores_descriptor_not_raw_payload() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-shared");
        let payload = b"large-hostcall-payload".to_vec();

        channel
            .send_shared_buffer(
                &handle,
                SharedSendInput {
                    region_id: 42,
                    payload: &payload,
                    trace_id: "trace-shared",
                    timestamp_ticks: 101,
                    decision_id: Some("dec-shared"),
                    policy_id: Some("policy-shared"),
                },
            )
            .expect("shared send");

        let received = channel
            .receive(&handle, "trace-shared-rx", 102, None, None)
            .expect("shared receive");

        let expected = ChannelPayload::Shared(SharedPayloadDescriptor {
            region_id: 42,
            payload_len: payload.len(),
            payload_hash: ContentHash::compute(&payload),
        });
        assert_eq!(received, expected);
    }

    #[test]
    fn session_key_derivation_binds_session_context() {
        let mut channel = SessionHostcallChannel::new();
        let handle_a = create_basic_session(&mut channel, "sess-context-a");
        let handle_b = create_basic_session(&mut channel, "sess-context-b");

        let key_a = channel
            .sessions
            .get(&handle_a.session_id)
            .expect("session a exists")
            .session_key;
        let key_b = channel
            .sessions
            .get(&handle_b.session_id)
            .expect("session b exists")
            .session_key;

        assert_ne!(
            key_a, key_b,
            "session key must be bound to session-specific HKDF context"
        );
    }

    #[test]
    fn deterministic_aead_nonce_is_reproducible() {
        let key = [0x11; 32];
        let nonce_a = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            42,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let nonce_b = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            42,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        assert_eq!(nonce_a, nonce_b);
    }

    #[test]
    fn deterministic_aead_nonce_changes_with_direction_sequence_and_key() {
        let key_a = [0x11; 32];
        let key_b = [0x22; 32];
        let base = derive_deterministic_aead_nonce(
            &key_a,
            DataPlaneDirection::HostToExtension,
            7,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let different_direction = derive_deterministic_aead_nonce(
            &key_a,
            DataPlaneDirection::ExtensionToHost,
            7,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let different_sequence = derive_deterministic_aead_nonce(
            &key_a,
            DataPlaneDirection::HostToExtension,
            8,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let different_key = derive_deterministic_aead_nonce(
            &key_b,
            DataPlaneDirection::HostToExtension,
            7,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");

        assert_ne!(base, different_direction);
        assert_ne!(base, different_sequence);
        assert_ne!(base, different_key);
    }

    #[test]
    fn deterministic_aead_nonce_respects_algorithm_nonce_lengths() {
        let key = [0x11; 32];
        let chacha = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let aes = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1,
            AeadAlgorithm::Aes256Gcm,
        )
        .expect("nonce derivation");
        let xchacha = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1,
            AeadAlgorithm::XChaCha20Poly1305,
        )
        .expect("nonce derivation");

        assert_eq!(chacha.as_bytes().len(), 12);
        assert_eq!(aes.as_bytes().len(), 12);
        assert_eq!(xchacha.as_bytes().len(), 24);
    }

    #[test]
    fn deterministic_aead_nonce_enforces_key_exhaustion_limits() {
        let key = [0x11; 32];
        let err = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            1u64 << 32,
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap_err();
        assert!(matches!(err, SessionChannelError::NonceExhausted { .. }));
    }

    #[test]
    fn deterministic_aead_associated_data_binds_session_and_metadata() {
        let ad = build_aead_associated_data("sess-ad", "hostcall.invoke", 0b1010);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"fe::hostcall::aead-ad");
        append_str(&mut expected, "sess-ad");
        append_str(&mut expected, "hostcall.invoke");
        expected.extend_from_slice(&0b1010u32.to_be_bytes());
        assert_eq!(ad, expected);
    }

    #[test]
    fn deterministic_aead_nonce_matches_golden_vector() {
        let key = [0xA5; 32];
        let nonce = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::ExtensionToHost,
            0x0102_0304_0506_0708,
            AeadAlgorithm::XChaCha20Poly1305,
        )
        .expect("nonce derivation");
        let actual_hex: String = nonce
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            actual_hex,
            "d2a705a45777211fb715eddd68fe343e370a1a766296fbed"
        );
    }

    #[test]
    fn structured_events_include_stable_keys() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-events");
        channel
            .send(
                &handle,
                b"evt".to_vec(),
                "trace-evt",
                101,
                Some("decision-evt"),
                Some("policy-evt"),
            )
            .expect("send");
        let _ = channel.receive(
            &handle,
            "trace-evt-rx",
            102,
            Some("decision-evt-rx"),
            Some("policy-evt"),
        );

        let events = channel.drain_events();
        assert!(events.iter().all(|event| !event.trace_id.is_empty()));
        assert!(events.iter().all(|event| !event.component.is_empty()));
        assert!(events.iter().all(|event| !event.event.is_empty()));
        assert!(events.iter().all(|event| !event.outcome.is_empty()));
        assert!(events.iter().all(|event| !event.session_id.is_empty()));
    }

    #[test]
    fn serialization_round_trip_for_envelope_and_event() {
        let envelope = HostcallEnvelope {
            session_id: "s".to_string(),
            extension_id: "e".to_string(),
            host_id: "h".to_string(),
            sequence: 7,
            payload: ChannelPayload::Inline(vec![1, 2, 3]),
            mac: AuthenticityHash::compute_keyed(b"k", b"v"),
            trace_id: "t".to_string(),
            sent_at_tick: 10,
        };
        let encoded = serde_json::to_string(&envelope).expect("serde deserialization should succeed");
        let decoded: HostcallEnvelope = serde_json::from_str(&encoded).expect("serde deserialization should succeed");
        assert_eq!(envelope, decoded);

        let event = SessionChannelEvent {
            trace_id: "trace".to_string(),
            decision_id: Some("dec".to_string()),
            policy_id: Some("policy".to_string()),
            component: "session_hostcall_channel".to_string(),
            event: "message_sent".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("FE-5000".to_string()),
            session_id: "s".to_string(),
            extension_id: "e".to_string(),
            host_id: "h".to_string(),
            sequence: Some(1),
            expected_min_seq: None,
            received_seq: None,
            drop_reason: None,
            source_principal: None,
            timestamp_ticks: 12,
        };
        let encoded_event = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let decoded_event: SessionChannelEvent = serde_json::from_str(&encoded_event).expect("serde deserialization should succeed");
        assert_eq!(event, decoded_event);
    }

    // -- SessionState Display --

    #[test]
    fn session_state_display_all_variants() {
        assert_eq!(SessionState::Init.to_string(), "init");
        assert_eq!(SessionState::Established.to_string(), "established");
        assert_eq!(SessionState::Expired.to_string(), "expired");
        assert_eq!(SessionState::Closed.to_string(), "closed");
    }

    // -- SequencePolicy Display --

    #[test]
    fn sequence_policy_display() {
        assert_eq!(SequencePolicy::Strict.to_string(), "strict");
        assert_eq!(SequencePolicy::Monotonic.to_string(), "monotonic");
    }

    // -- SessionConfig defaults --

    #[test]
    fn session_config_default_values() {
        let cfg = SessionConfig::default();
        assert_eq!(cfg.max_lifetime_ticks, 10_000);
        assert_eq!(cfg.max_messages, 10_000);
        assert_eq!(cfg.max_buffered_messages, 256);
        assert_eq!(cfg.sequence_policy, SequencePolicy::Monotonic);
        assert_eq!(cfg.replay_drop_threshold, 8);
        assert_eq!(cfg.replay_drop_window_ticks, 1_000);
    }

    // -- AeadAlgorithm helpers --

    #[test]
    fn aead_algorithm_nonce_lengths() {
        assert_eq!(AeadAlgorithm::ChaCha20Poly1305.nonce_len(), 12);
        assert_eq!(AeadAlgorithm::Aes256Gcm.nonce_len(), 12);
        assert_eq!(AeadAlgorithm::XChaCha20Poly1305.nonce_len(), 24);
    }

    #[test]
    fn aead_algorithm_max_messages_per_key() {
        assert_eq!(AeadAlgorithm::Aes256Gcm.max_messages_per_key(), 1u64 << 32);
        assert_eq!(
            AeadAlgorithm::ChaCha20Poly1305.max_messages_per_key(),
            u64::MAX
        );
        assert_eq!(
            AeadAlgorithm::XChaCha20Poly1305.max_messages_per_key(),
            u64::MAX
        );
    }

    // -- Handshake validation --

    #[test]
    fn empty_session_id_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let hs = handshake("", "trace", 100);
        let err = channel
            .create_session(
                hs,
                &signing_key(1),
                &signing_key(2),
                SessionConfig::default(),
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidIdentity { .. }));
    }

    #[test]
    fn empty_extension_id_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let mut hs = handshake("sess-1", "trace", 100);
        hs.extension_id = String::new();
        let err = channel
            .create_session(
                hs,
                &signing_key(1),
                &signing_key(2),
                SessionConfig::default(),
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidIdentity { .. }));
    }

    #[test]
    fn too_long_identity_field_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let mut hs = handshake("sess-1", "trace", 100);
        hs.host_id = "x".repeat(129);
        let err = channel
            .create_session(
                hs,
                &signing_key(1),
                &signing_key(2),
                SessionConfig::default(),
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidIdentity { .. }));
    }

    #[test]
    fn same_extension_and_host_id_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let mut hs = handshake("sess-1", "trace", 100);
        hs.host_id = hs.extension_id.clone();
        let err = channel
            .create_session(
                hs,
                &signing_key(1),
                &signing_key(2),
                SessionConfig::default(),
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidHandshake { .. }));
    }

    #[test]
    fn duplicate_session_id_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let _ = create_basic_session(&mut channel, "dup-sess");
        let err = channel
            .create_session(
                handshake("dup-sess", "trace", 200),
                &signing_key(1),
                &signing_key(2),
                SessionConfig::default(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionAlreadyExists { .. }
        ));
    }

    // -- Config validation --

    #[test]
    fn zero_max_messages_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let err = channel
            .create_session(
                handshake("sess-cfg", "trace", 100),
                &signing_key(1),
                &signing_key(2),
                SessionConfig {
                    max_messages: 0,
                    ..SessionConfig::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidHandshake { .. }));
    }

    #[test]
    fn zero_max_lifetime_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let err = channel
            .create_session(
                handshake("sess-lt", "trace", 100),
                &signing_key(1),
                &signing_key(2),
                SessionConfig {
                    max_lifetime_ticks: 0,
                    ..SessionConfig::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidHandshake { .. }));
    }

    #[test]
    fn zero_max_buffered_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let err = channel
            .create_session(
                handshake("sess-buf", "trace", 100),
                &signing_key(1),
                &signing_key(2),
                SessionConfig {
                    max_buffered_messages: 0,
                    ..SessionConfig::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidHandshake { .. }));
    }

    #[test]
    fn replay_threshold_without_window_rejected() {
        let mut channel = SessionHostcallChannel::new();
        let err = channel
            .create_session(
                handshake("sess-rw", "trace", 100),
                &signing_key(1),
                &signing_key(2),
                SessionConfig {
                    replay_drop_threshold: 5,
                    replay_drop_window_ticks: 0,
                    ..SessionConfig::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::InvalidHandshake { .. }));
    }

    // -- Close session --

    #[test]
    fn close_session_transitions_to_closed() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-close");
        channel
            .close_session(&handle, "trace-close", 200, None, None)
            .expect("close should succeed");
        assert_eq!(channel.session_state(&handle), Some(SessionState::Closed));
    }

    #[test]
    fn close_already_closed_session_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-close-twice");
        channel
            .close_session(&handle, "trace-close", 200, None, None)
            .expect("first close");
        let err = channel
            .close_session(&handle, "trace-close-2", 201, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionNotEstablished { .. }
        ));
    }

    #[test]
    fn close_emits_event() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-close-evt");
        let _ = channel.drain_events();
        channel
            .close_session(&handle, "trace-close", 200, Some("dec-c"), Some("pol-c"))
            .expect("serde deserialization should succeed");
        let events = channel.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "session_closed");
        assert_eq!(events[0].decision_id.as_deref(), Some("dec-c"));
        assert_eq!(events[0].policy_id.as_deref(), Some("pol-c"));
    }

    // -- Session not found --

    #[test]
    fn send_on_missing_session_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = SessionHandle {
            session_id: "nonexistent".to_string(),
        };
        let err = channel
            .send(&handle, b"x".to_vec(), "trace", 100, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::SessionNotFound { .. }));
    }

    #[test]
    fn receive_on_missing_session_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = SessionHandle {
            session_id: "nonexistent".to_string(),
        };
        let err = channel
            .receive(&handle, "trace", 100, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::SessionNotFound { .. }));
    }

    #[test]
    fn close_missing_session_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = SessionHandle {
            session_id: "nonexistent".to_string(),
        };
        let err = channel
            .close_session(&handle, "trace", 100, None, None)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::SessionNotFound { .. }));
    }

    // -- Queue/state for missing sessions --

    #[test]
    fn queue_len_returns_none_for_missing_session() {
        let channel = SessionHostcallChannel::new();
        let handle = SessionHandle {
            session_id: "nonexistent".to_string(),
        };
        assert_eq!(channel.queue_len(&handle), None);
    }

    #[test]
    fn session_state_returns_none_for_missing_session() {
        let channel = SessionHostcallChannel::new();
        let handle = SessionHandle {
            session_id: "nonexistent".to_string(),
        };
        assert_eq!(channel.session_state(&handle), None);
    }

    // -- No message available --

    #[test]
    fn receive_on_empty_queue_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-empty-q");
        let err = channel
            .receive(&handle, "trace", 101, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::NoMessageAvailable { .. }
        ));
    }

    // -- Send on closed session --

    #[test]
    fn send_on_closed_session_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-closed-send");
        channel
            .close_session(&handle, "trace-close", 200, None, None)
            .expect("serde deserialization should succeed");
        let err = channel
            .send(&handle, b"x".to_vec(), "trace", 201, None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionNotEstablished { .. }
        ));
    }

    // -- Backpressure signal on non-established session --

    #[test]
    fn backpressure_signal_on_closed_session_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-bp-closed");
        channel
            .close_session(&handle, "trace-close", 200, None, None)
            .expect("serde deserialization should succeed");
        let err = channel
            .authenticated_backpressure_signal(&handle, 1, 1, "trace", 201)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionNotEstablished { .. }
        ));
    }

    #[test]
    fn verify_signal_after_session_close_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-verify-after-close");
        let signal = channel
            .authenticated_backpressure_signal(&handle, 1, 1, "trace", 101)
            .expect("serde deserialization should succeed");
        channel
            .close_session(&handle, "trace-close", 200, None, None)
            .expect("serde deserialization should succeed");

        let err = channel
            .verify_authenticated_signal(&handle, &signal)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionNotEstablished {
                state: SessionState::Closed,
                ..
            }
        ));
    }

    #[test]
    fn verify_signal_duplicate_replay_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-verify-replay");
        let signal = channel
            .authenticated_backpressure_signal(&handle, 1, 1, "trace", 101)
            .expect("serde deserialization should succeed");

        channel
            .verify_authenticated_signal(&handle, &signal)
            .expect("first verification consumes signal sequence");
        let err = channel
            .verify_authenticated_signal(&handle, &signal)
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));
    }

    #[test]
    fn verify_signal_with_wrong_principal_binding_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-verify-principal");
        let mut signal = channel
            .authenticated_backpressure_signal(&handle, 1, 1, "trace", 101)
            .expect("serde deserialization should succeed");
        signal.extension_id = "other-extension".to_string();

        let err = channel
            .verify_authenticated_signal(&handle, &signal)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionBindingMismatch { .. }
        ));
    }

    // -- verify_authenticated_signal with wrong session_id --

    #[test]
    fn verify_signal_with_wrong_session_id_fails() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-verify-sig");
        let mut signal = channel
            .authenticated_backpressure_signal(&handle, 0, 1, "trace", 101)
            .expect("serde deserialization should succeed");
        signal.session_id = "wrong-session".to_string();
        let err = channel
            .verify_authenticated_signal(&handle, &signal)
            .unwrap_err();
        assert!(matches!(
            err,
            SessionChannelError::SessionBindingMismatch { .. }
        ));
    }

    // -- SessionChannelError Display --

    #[test]
    fn session_channel_error_display_all_variants() {
        let cases: Vec<(SessionChannelError, &str)> = vec![
            (
                SessionChannelError::InvalidIdentity {
                    field: "session_id".to_string(),
                },
                "session_id",
            ),
            (
                SessionChannelError::InvalidHandshake {
                    detail: "bad".to_string(),
                },
                "bad",
            ),
            (
                SessionChannelError::SessionAlreadyExists {
                    session_id: "s1".to_string(),
                },
                "s1",
            ),
            (
                SessionChannelError::SessionNotFound {
                    session_id: "s2".to_string(),
                },
                "s2",
            ),
            (
                SessionChannelError::SessionNotEstablished {
                    session_id: "s3".to_string(),
                    state: SessionState::Closed,
                },
                "closed",
            ),
            (
                SessionChannelError::SessionExpired {
                    session_id: "s4".to_string(),
                    reason: "timeout".to_string(),
                },
                "timeout",
            ),
            (
                SessionChannelError::Backpressure {
                    session_id: "s5".to_string(),
                    pending: 10,
                    limit: 5,
                },
                "pending=10",
            ),
            (
                SessionChannelError::NoMessageAvailable {
                    session_id: "s6".to_string(),
                },
                "no message",
            ),
            (
                SessionChannelError::SessionBindingMismatch {
                    expected_session_id: "a".to_string(),
                    actual_session_id: "b".to_string(),
                },
                "binding mismatch",
            ),
            (
                SessionChannelError::MacMismatch {
                    session_id: "s7".to_string(),
                    sequence: 42,
                },
                "42",
            ),
            (
                SessionChannelError::InvalidControlSignal {
                    session_id: "s7c".to_string(),
                    detail: "bad payload".to_string(),
                },
                "bad payload",
            ),
            (
                SessionChannelError::ReplayDetected {
                    session_id: "s8".to_string(),
                    sequence: 3,
                    last_seen: 5,
                },
                "replay",
            ),
            (
                SessionChannelError::OutOfOrderDetected {
                    session_id: "s9".to_string(),
                    sequence: 7,
                    expected_min: 4,
                },
                "out-of-order",
            ),
            (
                SessionChannelError::NonceExhausted {
                    sequence: 100,
                    limit: 50,
                    algorithm: AeadAlgorithm::Aes256Gcm,
                },
                "nonce budget exhausted",
            ),
        ];
        for (err, expected_substring) in cases {
            let s = err.to_string();
            assert!(
                s.contains(expected_substring),
                "'{s}' should contain '{expected_substring}'"
            );
        }
    }

    // -- SessionChannelError serde roundtrip --

    #[test]
    fn session_channel_error_serde_roundtrip() {
        let errors = vec![
            SessionChannelError::InvalidIdentity {
                field: "f".to_string(),
            },
            SessionChannelError::InvalidHandshake {
                detail: "d".to_string(),
            },
            SessionChannelError::SessionAlreadyExists {
                session_id: "s".to_string(),
            },
            SessionChannelError::SessionNotFound {
                session_id: "s".to_string(),
            },
            SessionChannelError::SessionNotEstablished {
                session_id: "s".to_string(),
                state: SessionState::Init,
            },
            SessionChannelError::SessionExpired {
                session_id: "s".to_string(),
                reason: "r".to_string(),
            },
            SessionChannelError::Backpressure {
                session_id: "s".to_string(),
                pending: 1,
                limit: 2,
            },
            SessionChannelError::NoMessageAvailable {
                session_id: "s".to_string(),
            },
            SessionChannelError::SessionBindingMismatch {
                expected_session_id: "a".to_string(),
                actual_session_id: "b".to_string(),
            },
            SessionChannelError::MacMismatch {
                session_id: "s".to_string(),
                sequence: 1,
            },
            SessionChannelError::InvalidControlSignal {
                session_id: "s".to_string(),
                detail: "d".to_string(),
            },
            SessionChannelError::ReplayDetected {
                session_id: "s".to_string(),
                sequence: 1,
                last_seen: 2,
            },
            SessionChannelError::OutOfOrderDetected {
                session_id: "s".to_string(),
                sequence: 5,
                expected_min: 3,
            },
            SessionChannelError::NonceExhausted {
                sequence: 100,
                limit: 50,
                algorithm: AeadAlgorithm::Aes256Gcm,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let restored: SessionChannelError = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, restored);
        }
    }

    // -- Serde roundtrips for types --

    #[test]
    fn session_state_serde_roundtrip() {
        for state in [
            SessionState::Init,
            SessionState::Established,
            SessionState::Expired,
            SessionState::Closed,
        ] {
            let json = serde_json::to_string(&state).expect("serde deserialization should succeed");
            let restored: SessionState = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(state, restored);
        }
    }

    #[test]
    fn sequence_policy_serde_roundtrip() {
        for policy in [SequencePolicy::Strict, SequencePolicy::Monotonic] {
            let json = serde_json::to_string(&policy).expect("serde deserialization should succeed");
            let restored: SequencePolicy = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(policy, restored);
        }
    }

    #[test]
    fn aead_algorithm_serde_roundtrip() {
        for alg in [
            AeadAlgorithm::ChaCha20Poly1305,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::XChaCha20Poly1305,
        ] {
            let json = serde_json::to_string(&alg).expect("serde deserialization should succeed");
            let restored: AeadAlgorithm = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(alg, restored);
        }
    }

    #[test]
    fn channel_payload_serde_roundtrip() {
        let payloads = vec![
            ChannelPayload::Inline(vec![1, 2, 3]),
            ChannelPayload::Shared(SharedPayloadDescriptor {
                region_id: 42,
                payload_len: 100,
                payload_hash: ContentHash::compute(b"test"),
            }),
            ChannelPayload::Backpressure(BackpressureSignal {
                pending_messages: 10,
                limit: 5,
            }),
        ];
        for payload in &payloads {
            let json = serde_json::to_string(payload).expect("serde deserialization should succeed");
            let restored: ChannelPayload = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*payload, restored);
        }
    }

    #[test]
    fn session_config_serde_roundtrip() {
        let cfg = SessionConfig::default();
        let json = serde_json::to_string(&cfg).expect("serde deserialization should succeed");
        let restored: SessionConfig = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(cfg, restored);
    }

    #[test]
    fn session_handshake_serde_roundtrip() {
        let hs = handshake("s1", "trace-1", 100);
        let json = serde_json::to_string(&hs).expect("serde deserialization should succeed");
        let restored: SessionHandshake = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(hs, restored);
    }

    #[test]
    fn replay_drop_reason_as_str_values() {
        assert_eq!(ReplayDropReason::Replay.as_str(), "replay");
        assert_eq!(ReplayDropReason::Duplicate.as_str(), "duplicate");
        assert_eq!(ReplayDropReason::OutOfOrder.as_str(), "out_of_order");
    }

    // -- Replay drop window reset --

    #[test]
    fn replay_drop_window_resets_after_window_ticks() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_session_with_config(
            &mut channel,
            "sess-window-reset",
            SessionConfig {
                replay_drop_threshold: 2,
                replay_drop_window_ticks: 10,
                ..SessionConfig::default()
            },
        );
        channel
            .send(&handle, b"first".to_vec(), "trace", 101, None, None)
            .expect("serde deserialization should succeed");

        let replay = {
            let session = channel.sessions.get(&handle.session_id).expect("serde deserialization should succeed");
            session.inbound.front().cloned().expect("serde deserialization should succeed")
        };

        let _ = channel.receive(&handle, "trace", 102, None, None).expect("serde deserialization should succeed");

        // First drop at tick 103 (within window).
        {
            let session = channel.sessions.get_mut(&handle.session_id).expect("serde deserialization should succeed");
            session.inbound.push_back(replay.clone());
        }
        let _ = channel.receive(&handle, "trace", 103, None, None);

        // Second drop at tick 120 (outside window — resets counter).
        channel
            .send(&handle, b"second".to_vec(), "trace", 115, None, None)
            .expect("serde deserialization should succeed");
        let replay2 = {
            let session = channel.sessions.get(&handle.session_id).expect("serde deserialization should succeed");
            session.inbound.front().cloned().expect("serde deserialization should succeed")
        };
        let _ = channel.receive(&handle, "trace", 116, None, None).expect("serde deserialization should succeed");

        {
            let session = channel.sessions.get_mut(&handle.session_id).expect("serde deserialization should succeed");
            session.inbound.push_back(replay2);
        }
        let err = channel
            .receive(&handle, "trace", 120, None, None)
            .unwrap_err();
        // Should NOT be SessionExpired because the window was reset.
        assert!(matches!(err, SessionChannelError::ReplayDetected { .. }));
        assert_eq!(
            channel.session_state(&handle),
            Some(SessionState::Established)
        );
    }

    // -- drain_events --

    #[test]
    fn drain_events_empties_the_buffer() {
        let mut channel = SessionHostcallChannel::new();
        let _ = create_basic_session(&mut channel, "sess-drain");
        let events = channel.drain_events();
        assert!(!events.is_empty());
        let events2 = channel.drain_events();
        assert!(events2.is_empty());
    }

    // -- send_shared_buffer sequence exhaustion --

    #[test]
    fn shared_buffer_sequence_exhaustion_expires_session() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-shared-exhaust");
        let session = channel.sessions.get_mut(&handle.session_id).expect("serde deserialization should succeed");
        session.next_sequence = u64::MAX;

        let err = channel
            .send_shared_buffer(
                &handle,
                SharedSendInput {
                    region_id: 1,
                    payload: b"test",
                    trace_id: "trace",
                    timestamp_ticks: 101,
                    decision_id: None,
                    policy_id: None,
                },
            )
            .unwrap_err();
        assert!(matches!(err, SessionChannelError::SessionExpired { .. }));
    }

    // -- Multiple messages in sequence --

    #[test]
    fn multiple_messages_increment_sequence() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-multi");
        let seq1 = channel
            .send(&handle, b"a".to_vec(), "trace", 101, None, None)
            .expect("serde deserialization should succeed");
        let seq2 = channel
            .send(&handle, b"b".to_vec(), "trace", 102, None, None)
            .expect("serde deserialization should succeed");
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(channel.queue_len(&handle), Some(2));
    }

    // -- Enrichment: missing serde roundtrips, std::error --

    #[test]
    fn data_plane_direction_serde_roundtrip() {
        let variants = [
            DataPlaneDirection::HostToExtension,
            DataPlaneDirection::ExtensionToHost,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let restored: DataPlaneDirection = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn replay_drop_reason_serde_roundtrip() {
        let variants = [
            ReplayDropReason::Replay,
            ReplayDropReason::Duplicate,
            ReplayDropReason::OutOfOrder,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let restored: ReplayDropReason = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn session_channel_error_std_error_trait() {
        let errs: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SessionChannelError::InvalidIdentity {
                field: "x".to_string(),
            }),
            Box::new(SessionChannelError::SessionNotFound {
                session_id: "s".to_string(),
            }),
            Box::new(SessionChannelError::SessionExpired {
                session_id: "s".to_string(),
                reason: "timeout".to_string(),
            }),
            Box::new(SessionChannelError::Backpressure {
                session_id: "s".to_string(),
                pending: 10,
                limit: 100,
            }),
            Box::new(SessionChannelError::NoMessageAvailable {
                session_id: "s".to_string(),
            }),
            Box::new(SessionChannelError::MacMismatch {
                session_id: "s".to_string(),
                sequence: 1,
            }),
            Box::new(SessionChannelError::InvalidControlSignal {
                session_id: "s".to_string(),
                detail: "bad payload".to_string(),
            }),
            Box::new(SessionChannelError::ReplayDetected {
                session_id: "s".to_string(),
                sequence: 1,
                last_seen: 0,
            }),
            Box::new(SessionChannelError::NonceExhausted {
                sequence: 100,
                limit: 100,
                algorithm: AeadAlgorithm::Aes256Gcm,
            }),
        ];
        for e in &errs {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: BackpressureSignal serde roundtrip --

    #[test]
    fn backpressure_signal_serde_roundtrip() {
        let signal = BackpressureSignal {
            pending_messages: 42,
            limit: 256,
        };
        let json = serde_json::to_string(&signal).expect("serde deserialization should succeed");
        let back: BackpressureSignal = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(signal, back);
    }

    // -- Enrichment: ChannelPayload serde roundtrip all variants --

    #[test]
    fn channel_payload_serde_roundtrip_inline() {
        let payload = ChannelPayload::Inline(vec![1, 2, 3]);
        let json = serde_json::to_string(&payload).expect("serde deserialization should succeed");
        let back: ChannelPayload = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(payload, back);
    }

    #[test]
    fn channel_payload_serde_roundtrip_shared() {
        let payload = ChannelPayload::Shared(SharedPayloadDescriptor {
            region_id: 7,
            payload_len: 1024,
            payload_hash: ContentHash::compute(b"data"),
        });
        let json = serde_json::to_string(&payload).expect("serde deserialization should succeed");
        let back: ChannelPayload = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(payload, back);
    }

    #[test]
    fn channel_payload_serde_roundtrip_backpressure() {
        let payload = ChannelPayload::Backpressure(BackpressureSignal {
            pending_messages: 10,
            limit: 100,
        });
        let json = serde_json::to_string(&payload).expect("serde deserialization should succeed");
        let back: ChannelPayload = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(payload, back);
    }

    // -- Enrichment: SessionHandle serde roundtrip --

    #[test]
    fn session_handle_serde_roundtrip() {
        let handle = SessionHandle {
            session_id: "sess-123".to_string(),
        };
        let json = serde_json::to_string(&handle).expect("serde deserialization should succeed");
        let back: SessionHandle = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(handle, back);
    }

    // -- Enrichment: SessionChannelError Display uniqueness --

    #[test]
    fn session_channel_error_display_all_distinct() {
        let variants: Vec<SessionChannelError> = vec![
            SessionChannelError::InvalidIdentity {
                field: "a".to_string(),
            },
            SessionChannelError::InvalidHandshake {
                detail: "b".to_string(),
            },
            SessionChannelError::SessionAlreadyExists {
                session_id: "s1".to_string(),
            },
            SessionChannelError::SessionNotFound {
                session_id: "s2".to_string(),
            },
            SessionChannelError::SessionNotEstablished {
                session_id: "s3".to_string(),
                state: SessionState::Init,
            },
            SessionChannelError::SessionExpired {
                session_id: "s4".to_string(),
                reason: "timeout".to_string(),
            },
            SessionChannelError::Backpressure {
                session_id: "s5".to_string(),
                pending: 10,
                limit: 50,
            },
            SessionChannelError::NoMessageAvailable {
                session_id: "s6".to_string(),
            },
            SessionChannelError::SessionBindingMismatch {
                expected_session_id: "s7".to_string(),
                actual_session_id: "s8".to_string(),
            },
            SessionChannelError::MacMismatch {
                session_id: "s9".to_string(),
                sequence: 1,
            },
            SessionChannelError::InvalidControlSignal {
                session_id: "s9c".to_string(),
                detail: "bad payload".to_string(),
            },
            SessionChannelError::ReplayDetected {
                session_id: "s10".to_string(),
                sequence: 5,
                last_seen: 3,
            },
            SessionChannelError::OutOfOrderDetected {
                session_id: "s11".to_string(),
                sequence: 2,
                expected_min: 5,
            },
            SessionChannelError::NonceExhausted {
                sequence: 100,
                limit: 100,
                algorithm: AeadAlgorithm::Aes256Gcm,
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = v.to_string();
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            variants.len(),
            "all error variants produce distinct messages"
        );
    }

    // -- Enrichment: DataPlaneDirection coverage --

    #[test]
    fn data_plane_direction_eq_and_ne() {
        assert_eq!(
            DataPlaneDirection::HostToExtension,
            DataPlaneDirection::HostToExtension
        );
        assert_ne!(
            DataPlaneDirection::HostToExtension,
            DataPlaneDirection::ExtensionToHost
        );
    }

    // -- Enrichment: fresh channel state --

    #[test]
    fn fresh_channel_has_no_sessions() {
        let mut channel = SessionHostcallChannel::new();
        assert!(channel.drain_events().is_empty());
    }

    #[test]
    fn fresh_channel_has_no_events() {
        let mut channel = SessionHostcallChannel::new();
        assert!(channel.drain_events().is_empty());
    }

    // -- Enrichment: SessionState Display all variants --

    #[test]
    fn session_state_display_covers_all() {
        let cases = [
            (SessionState::Init, "init"),
            (SessionState::Established, "established"),
            (SessionState::Expired, "expired"),
            (SessionState::Closed, "closed"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (state, expected) in &cases {
            let s = state.to_string();
            assert_eq!(&s, *expected);
            seen.insert(s);
        }
        assert_eq!(seen.len(), 4);
    }

    // -- Enrichment: SequencePolicy serde all variants --

    #[test]
    fn sequence_policy_serde_all_variants() {
        for policy in [SequencePolicy::Strict, SequencePolicy::Monotonic] {
            let json = serde_json::to_string(&policy).expect("serde deserialization should succeed");
            let restored: SequencePolicy = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(policy, restored);
        }
    }

    // -- Enrichment: SessionState serde all variants --

    #[test]
    fn session_state_serde_all_variants() {
        for state in [
            SessionState::Init,
            SessionState::Established,
            SessionState::Expired,
            SessionState::Closed,
        ] {
            let json = serde_json::to_string(&state).expect("serde deserialization should succeed");
            let restored: SessionState = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(state, restored);
        }
    }

    // -- Enrichment: AeadAlgorithm nonce_len and max_messages_per_key --

    #[test]
    fn aead_algorithm_nonce_len_all_variants() {
        assert_eq!(AeadAlgorithm::ChaCha20Poly1305.nonce_len(), 12);
        assert_eq!(AeadAlgorithm::Aes256Gcm.nonce_len(), 12);
        assert_eq!(AeadAlgorithm::XChaCha20Poly1305.nonce_len(), 24);
    }

    #[test]
    fn aead_algorithm_max_messages_per_key_values() {
        assert_eq!(AeadAlgorithm::Aes256Gcm.max_messages_per_key(), 1u64 << 32);
        assert_eq!(
            AeadAlgorithm::ChaCha20Poly1305.max_messages_per_key(),
            u64::MAX
        );
        assert_eq!(
            AeadAlgorithm::XChaCha20Poly1305.max_messages_per_key(),
            u64::MAX
        );
    }

    // -- Enrichment: AeadAlgorithm serde all variants --

    #[test]
    fn aead_algorithm_serde_all_variants() {
        for alg in [
            AeadAlgorithm::ChaCha20Poly1305,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::XChaCha20Poly1305,
        ] {
            let json = serde_json::to_string(&alg).expect("serde deserialization should succeed");
            let restored: AeadAlgorithm = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(alg, restored);
        }
    }

    // -- Enrichment: SharedPayloadDescriptor serde --

    #[test]
    fn shared_payload_descriptor_serde_roundtrip() {
        let desc = SharedPayloadDescriptor {
            region_id: 42,
            payload_len: 1024,
            payload_hash: ContentHash::compute(b"test-payload"),
        };
        let json = serde_json::to_string(&desc).expect("serde deserialization should succeed");
        let restored: SharedPayloadDescriptor = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(desc, restored);
    }

    // -- Enrichment: BackpressureSignal serde --

    #[test]
    fn backpressure_signal_fields_and_serde() {
        let signal = BackpressureSignal {
            pending_messages: 200,
            limit: 256,
        };
        let json = serde_json::to_string(&signal).expect("serde deserialization should succeed");
        let restored: BackpressureSignal = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(signal, restored);
        assert_eq!(restored.pending_messages, 200);
        assert_eq!(restored.limit, 256);
    }

    // -- Enrichment: HostcallEnvelope serde --

    #[test]
    fn hostcall_envelope_serde_roundtrip() {
        let envelope = HostcallEnvelope {
            session_id: "sess-1".into(),
            extension_id: "ext-1".into(),
            host_id: "host-1".into(),
            sequence: 7,
            payload: ChannelPayload::Inline(vec![0xDE, 0xAD]),
            mac: AuthenticityHash::compute_keyed(b"key", b"data"),
            trace_id: "t-1".into(),
            sent_at_tick: 100,
        };
        let json = serde_json::to_string(&envelope).expect("serde deserialization should succeed");
        let restored: HostcallEnvelope = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(envelope, restored);
    }

    // -- Enrichment: HandshakeRequest serde --

    #[test]
    fn handshake_request_serde_roundtrip() {
        let sk = SigningKey::from_bytes([0xAA; 32]).expect("serde deserialization should succeed");
        let req = HandshakeRequest {
            session_id: "sess-1".into(),
            extension_id: "ext-1".into(),
            host_id: "host-1".into(),
            extension_nonce: 42,
            timestamp_ticks: 1000,
            extension_key: sk.verification_key(),
            signature: sign_preimage(&sk, b"test-preimage").expect("serde deserialization should succeed"),
        };
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let restored: HandshakeRequest = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(req, restored);
    }

    // -- Enrichment: HandshakeResponse serde --

    #[test]
    fn handshake_response_serde_roundtrip() {
        let sk = SigningKey::from_bytes([0xAA; 32]).expect("serde deserialization should succeed");
        let resp = HandshakeResponse {
            session_id: "sess-1".into(),
            extension_nonce: 42,
            host_nonce: 99,
            host_key: sk.verification_key(),
            signature: sign_preimage(&sk, b"test-preimage").expect("serde deserialization should succeed"),
        };
        let json = serde_json::to_string(&resp).expect("serde deserialization should succeed");
        let restored: HandshakeResponse = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(resp, restored);
    }

    // -- Enrichment: SessionHandshake serde --

    #[test]
    fn session_handshake_serde_all_fields() {
        let hs = SessionHandshake {
            session_id: "sess-1".into(),
            extension_id: "ext-1".into(),
            host_id: "host-1".into(),
            extension_nonce: 42,
            host_nonce: 99,
            timestamp_ticks: 500,
            trace_id: "t-1".into(),
        };
        let json = serde_json::to_string(&hs).expect("serde deserialization should succeed");
        let restored: SessionHandshake = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(hs, restored);
        assert_eq!(restored.extension_nonce, 42);
        assert_eq!(restored.host_nonce, 99);
    }

    // -- Enrichment: SessionChannelEvent serde --

    #[test]
    fn session_channel_event_serde_roundtrip() {
        let event = SessionChannelEvent {
            trace_id: "t-1".into(),
            decision_id: Some("d-1".into()),
            policy_id: Some("p-1".into()),
            component: "session_hostcall_channel".into(),
            event: "message_sent".into(),
            outcome: "ok".into(),
            error_code: None,
            session_id: "sess-1".into(),
            extension_id: "ext-1".into(),
            host_id: "host-1".into(),
            sequence: Some(1),
            expected_min_seq: None,
            received_seq: Some(1),
            drop_reason: None,
            source_principal: Some("ext-1".into()),
            timestamp_ticks: 100,
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: SessionChannelEvent = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    // -- Enrichment: ReplayDropReason as_str all variants --

    #[test]
    fn replay_drop_reason_as_str_all_variants() {
        assert_eq!(ReplayDropReason::Replay.as_str(), "replay");
        assert_eq!(ReplayDropReason::Duplicate.as_str(), "duplicate");
        assert_eq!(ReplayDropReason::OutOfOrder.as_str(), "out_of_order");
    }

    // -- Enrichment: build_aead_associated_data deterministic --

    #[test]
    fn build_aead_associated_data_deterministic() {
        let ad1 = build_aead_associated_data("sess-1", "hostcall", 0);
        let ad2 = build_aead_associated_data("sess-1", "hostcall", 0);
        assert_eq!(ad1, ad2);
        assert!(!ad1.is_empty());

        // Different session_id produces different AD
        let ad3 = build_aead_associated_data("sess-2", "hostcall", 0);
        assert_ne!(ad1, ad3);

        // Different flags produce different AD
        let ad4 = build_aead_associated_data("sess-1", "hostcall", 1);
        assert_ne!(ad1, ad4);
    }

    // -- Enrichment: SessionConfig default serde roundtrip --

    #[test]
    fn session_config_default_serde_preserves_defaults() {
        let config = SessionConfig::default();
        let json = serde_json::to_string(&config).expect("serde deserialization should succeed");
        let restored: SessionConfig = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(config, restored);
        assert_eq!(restored.max_lifetime_ticks, 10_000);
        assert_eq!(restored.max_messages, 10_000);
        assert_eq!(restored.sequence_policy, SequencePolicy::Monotonic);
    }

    // -- Enrichment: DeterministicNonce as_bytes --

    #[test]
    fn deterministic_nonce_as_bytes_matches_algorithm_len() {
        let key = [0u8; 32];
        let nonce = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            0,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("serde deserialization should succeed");
        assert_eq!(nonce.as_bytes().len(), 12);

        let nonce_x = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::ExtensionToHost,
            0,
            AeadAlgorithm::XChaCha20Poly1305,
        )
        .expect("serde deserialization should succeed");
        assert_eq!(nonce_x.as_bytes().len(), 24);
    }

    // -- Enrichment: SessionChannelError From<SignatureError> --

    #[test]
    fn session_channel_error_from_signature_error() {
        let sk = SigningKey::from_bytes([0xBB; 32]).expect("serde deserialization should succeed");
        let sig_err = SignatureError::VerificationFailed {
            signer: sk.verification_key(),
            reason: "test mismatch".into(),
        };
        let ch_err: SessionChannelError = sig_err.into();
        match &ch_err {
            SessionChannelError::SignatureFailure(_) => {}
            other => panic!("expected SignatureFailure, got: {other}"),
        }
        assert!(!ch_err.to_string().is_empty());
    }

    // -- Enrichment: SessionHandle clone and eq --

    #[test]
    fn session_handle_clone_and_eq() {
        let h1 = SessionHandle {
            session_id: "sess-abc".into(),
        };
        let h2 = h1.clone();
        assert_eq!(h1, h2);

        let h3 = SessionHandle {
            session_id: "sess-xyz".into(),
        };
        assert_ne!(h1, h3);
    }

    // ── Enrichment: serde roundtrip tests ────────────────────────────

    #[test]
    fn shared_payload_descriptor_serde_roundtrip_alt() {
        let desc = SharedPayloadDescriptor {
            region_id: 42,
            payload_len: 1024,
            payload_hash: ContentHash::compute(b"shared-payload"),
        };
        let json = serde_json::to_string(&desc).expect("serde deserialization should succeed");
        let back: SharedPayloadDescriptor = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, desc);
    }

    #[test]
    fn backpressure_signal_serde_roundtrip_alt() {
        let sig = BackpressureSignal {
            pending_messages: 100,
            limit: 50,
        };
        let json = serde_json::to_string(&sig).expect("serde deserialization should succeed");
        let back: BackpressureSignal = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, sig);
    }

    #[test]
    fn channel_payload_serde_roundtrip_all_variants() {
        let variants = [
            ChannelPayload::Inline(vec![1, 2, 3, 4]),
            ChannelPayload::Shared(SharedPayloadDescriptor {
                region_id: 7,
                payload_len: 256,
                payload_hash: ContentHash::compute(b"shared"),
            }),
            ChannelPayload::Backpressure(BackpressureSignal {
                pending_messages: 50,
                limit: 25,
            }),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: ChannelPayload = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn session_config_serde_roundtrip_custom() {
        let cfg = SessionConfig {
            max_lifetime_ticks: 5000,
            max_messages: 200,
            max_buffered_messages: 32,
            sequence_policy: SequencePolicy::Monotonic,
            replay_drop_threshold: 10,
            replay_drop_window_ticks: 500,
        };
        let json = serde_json::to_string(&cfg).expect("serde deserialization should succeed");
        let back: SessionConfig = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, cfg);
    }

    #[test]
    fn channel_payload_inline_empty() {
        let p = ChannelPayload::Inline(vec![]);
        let json = serde_json::to_string(&p).expect("serde deserialization should succeed");
        let back: ChannelPayload = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, p);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 3 --

    #[test]
    fn signature_failure_display_contains_inner_error() {
        let sk = SigningKey::from_bytes([0xCC; 32]).expect("serde deserialization should succeed");
        let sig_err = SignatureError::VerificationFailed {
            signer: sk.verification_key(),
            reason: "mismatch detail".into(),
        };
        let ch_err = SessionChannelError::SignatureFailure(sig_err);
        let display = ch_err.to_string();
        assert!(
            display.starts_with("signature failure:"),
            "SignatureFailure Display should start with 'signature failure:'"
        );
        assert!(
            display.contains("mismatch detail"),
            "SignatureFailure Display should include inner reason"
        );
    }

    #[test]
    fn signature_failure_serde_roundtrip() {
        let sk = SigningKey::from_bytes([0xDD; 32]).expect("serde deserialization should succeed");
        let sig_err = SignatureError::VerificationFailed {
            signer: sk.verification_key(),
            reason: "bad sig".into(),
        };
        let err = SessionChannelError::SignatureFailure(sig_err);
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let restored: SessionChannelError = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, restored);
    }

    #[test]
    fn deterministic_nonce_serde_roundtrip() {
        let key = [0x33; 32];
        let nonce = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            5,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&nonce).expect("serde deserialization should succeed");
        let restored: DeterministicNonce = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(nonce, restored);
        assert_eq!(restored.as_bytes().len(), 12);
    }

    #[test]
    fn identity_field_at_128_chars_accepted() {
        let mut channel = SessionHostcallChannel::new();
        let mut hs = handshake("sess-boundary", "trace", 100);
        hs.extension_id = "x".repeat(128);
        // Should succeed since 128 is exactly at the limit.
        let result = channel.create_session(
            hs,
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        );
        assert!(result.is_ok(), "128-char identity should be accepted");
    }

    #[test]
    fn aead_algorithm_as_tag_all_distinct() {
        let tags = [
            AeadAlgorithm::ChaCha20Poly1305.as_tag(),
            AeadAlgorithm::Aes256Gcm.as_tag(),
            AeadAlgorithm::XChaCha20Poly1305.as_tag(),
        ];
        let set: std::collections::BTreeSet<u8> = tags.iter().copied().collect();
        assert_eq!(set.len(), 3, "AEAD algorithm tags must be distinct");
    }

    #[test]
    fn data_plane_direction_as_byte_distinct() {
        assert_ne!(
            DataPlaneDirection::HostToExtension.as_byte(),
            DataPlaneDirection::ExtensionToHost.as_byte(),
            "direction bytes must differ"
        );
    }

    #[test]
    fn replay_drop_reason_as_str_all_distinct() {
        let strs: std::collections::BTreeSet<&str> = [
            ReplayDropReason::Replay.as_str(),
            ReplayDropReason::Duplicate.as_str(),
            ReplayDropReason::OutOfOrder.as_str(),
        ]
        .into_iter()
        .collect();
        assert_eq!(strs.len(), 3, "all replay drop reasons must be distinct");
    }

    #[test]
    fn event_component_is_session_hostcall_channel() {
        let mut channel = SessionHostcallChannel::new();
        let _ = create_basic_session(&mut channel, "sess-comp");
        let events = channel.drain_events();
        assert!(!events.is_empty());
        for event in &events {
            assert_eq!(
                event.component, "session_hostcall_channel",
                "component must be 'session_hostcall_channel'"
            );
        }
    }

    #[test]
    fn hkdf_expand_zero_length_returns_empty() {
        let prk = [0xAA; 32];
        let result = hkdf_expand(&prk, b"info", 0);
        assert!(result.is_empty());
    }

    #[test]
    fn send_event_includes_sequence_and_decision_id() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-send-evt");
        let _ = channel.drain_events(); // clear create event
        channel
            .send(
                &handle,
                b"data".to_vec(),
                "trace-se",
                101,
                Some("dec-se"),
                Some("pol-se"),
            )
            .expect("serde deserialization should succeed");
        let events = channel.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "message_sent");
        assert_eq!(events[0].sequence, Some(1));
        assert_eq!(events[0].decision_id.as_deref(), Some("dec-se"));
        assert_eq!(events[0].policy_id.as_deref(), Some("pol-se"));
    }

    #[test]
    fn shared_send_event_name_is_shared_payload_sent() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-shared-evt");
        let _ = channel.drain_events();
        channel
            .send_shared_buffer(
                &handle,
                SharedSendInput {
                    region_id: 1,
                    payload: b"data",
                    trace_id: "trace-shared-evt",
                    timestamp_ticks: 101,
                    decision_id: None,
                    policy_id: None,
                },
            )
            .expect("serde deserialization should succeed");
        let events = channel.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "shared_payload_sent");
    }

    #[test]
    fn receive_event_name_is_message_received() {
        let mut channel = SessionHostcallChannel::new();
        let handle = create_basic_session(&mut channel, "sess-recv-evt");
        channel
            .send(&handle, b"x".to_vec(), "trace", 101, None, None)
            .expect("serde deserialization should succeed");
        let _ = channel.drain_events();
        channel
            .receive(&handle, "trace-recv", 102, None, None)
            .expect("serde deserialization should succeed");
        let events = channel.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "message_received");
    }
}
