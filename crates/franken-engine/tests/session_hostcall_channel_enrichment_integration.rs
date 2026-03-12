#![forbid(unsafe_code)]
//! Enrichment integration tests for `session_hostcall_channel`.
//!
//! Adds ReplayDropReason as_str exact values, JSON field-name stability,
//! Debug distinctness, serde exact tags, and config field validation
//! beyond the existing 51 integration tests.

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

use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::session_hostcall_channel::{
    AeadAlgorithm, BackpressureSignal, ChannelPayload, DataPlaneDirection, DeterministicNonce,
    HostcallEnvelope, ReplayDropReason, SequencePolicy, SessionChannelError, SessionChannelEvent,
    SessionConfig, SessionHandle, SessionHandshake, SessionHostcallChannel, SessionState,
    SharedPayloadDescriptor, build_aead_associated_data, derive_deterministic_aead_nonce,
};
use frankenengine_engine::signature_preimage::SigningKey;

// ===========================================================================
// 1) ReplayDropReason — serde roundtrip and Debug distinctness
// ===========================================================================

#[test]
fn serde_roundtrip_replay_drop_reason_all() {
    for r in [
        ReplayDropReason::Replay,
        ReplayDropReason::Duplicate,
        ReplayDropReason::OutOfOrder,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let rt: ReplayDropReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, rt);
    }
}

// ===========================================================================
// 2) SessionState — Display exact values
// ===========================================================================

#[test]
fn session_state_display_init() {
    assert_eq!(SessionState::Init.to_string(), "init");
}

#[test]
fn session_state_display_established() {
    assert_eq!(SessionState::Established.to_string(), "established");
}

#[test]
fn session_state_display_expired() {
    assert_eq!(SessionState::Expired.to_string(), "expired");
}

#[test]
fn session_state_display_closed() {
    assert_eq!(SessionState::Closed.to_string(), "closed");
}

// ===========================================================================
// 3) SequencePolicy — Display exact values
// ===========================================================================

#[test]
fn sequence_policy_display_strict() {
    assert_eq!(SequencePolicy::Strict.to_string(), "strict");
}

#[test]
fn sequence_policy_display_monotonic() {
    assert_eq!(SequencePolicy::Monotonic.to_string(), "monotonic");
}

// ===========================================================================
// 4) Debug distinctness — SessionState
// ===========================================================================

#[test]
fn debug_distinct_session_state() {
    let variants = [
        format!("{:?}", SessionState::Init),
        format!("{:?}", SessionState::Established),
        format!("{:?}", SessionState::Expired),
        format!("{:?}", SessionState::Closed),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 5) Debug distinctness — SequencePolicy
// ===========================================================================

#[test]
fn debug_distinct_sequence_policy() {
    let variants = [
        format!("{:?}", SequencePolicy::Strict),
        format!("{:?}", SequencePolicy::Monotonic),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 2);
}

// ===========================================================================
// 6) Debug distinctness — AeadAlgorithm
// ===========================================================================

#[test]
fn debug_distinct_aead_algorithm() {
    let variants = [
        format!("{:?}", AeadAlgorithm::ChaCha20Poly1305),
        format!("{:?}", AeadAlgorithm::Aes256Gcm),
        format!("{:?}", AeadAlgorithm::XChaCha20Poly1305),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 7) Debug distinctness — DataPlaneDirection
// ===========================================================================

#[test]
fn debug_distinct_data_plane_direction() {
    let variants = [
        format!("{:?}", DataPlaneDirection::HostToExtension),
        format!("{:?}", DataPlaneDirection::ExtensionToHost),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 2);
}

// ===========================================================================
// 8) Debug distinctness — ReplayDropReason
// ===========================================================================

#[test]
fn debug_distinct_replay_drop_reason() {
    let variants = [
        format!("{:?}", ReplayDropReason::Replay),
        format!("{:?}", ReplayDropReason::Duplicate),
        format!("{:?}", ReplayDropReason::OutOfOrder),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 9) SessionConfig — default exact values
// ===========================================================================

#[test]
fn session_config_default_max_lifetime_ticks() {
    let c = SessionConfig::default();
    assert_eq!(c.max_lifetime_ticks, 10_000);
}

#[test]
fn session_config_default_max_messages() {
    let c = SessionConfig::default();
    assert_eq!(c.max_messages, 10_000);
}

#[test]
fn session_config_default_max_buffered_messages() {
    let c = SessionConfig::default();
    assert_eq!(c.max_buffered_messages, 256);
}

#[test]
fn session_config_default_sequence_policy() {
    let c = SessionConfig::default();
    assert_eq!(c.sequence_policy, SequencePolicy::Monotonic);
}

#[test]
fn session_config_default_replay_drop_threshold() {
    let c = SessionConfig::default();
    assert_eq!(c.replay_drop_threshold, 8);
}

#[test]
fn session_config_default_replay_drop_window_ticks() {
    let c = SessionConfig::default();
    assert_eq!(c.replay_drop_window_ticks, 1_000);
}

// ===========================================================================
// 10) JSON field-name stability — SessionConfig
// ===========================================================================

#[test]
fn json_fields_session_config() {
    let c = SessionConfig::default();
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "max_lifetime_ticks",
        "max_messages",
        "max_buffered_messages",
        "sequence_policy",
        "replay_drop_threshold",
        "replay_drop_window_ticks",
    ] {
        assert!(obj.contains_key(key), "SessionConfig missing field: {key}");
    }
}

// ===========================================================================
// 11) JSON field-name stability — BackpressureSignal
// ===========================================================================

#[test]
fn json_fields_backpressure_signal() {
    let bs = BackpressureSignal {
        pending_messages: 100,
        limit: 256,
    };
    let v: serde_json::Value = serde_json::to_value(&bs).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["pending_messages", "limit"] {
        assert!(
            obj.contains_key(key),
            "BackpressureSignal missing field: {key}"
        );
    }
}

// ===========================================================================
// 12) JSON field-name stability — SharedPayloadDescriptor
// ===========================================================================

#[test]
fn json_fields_shared_payload_descriptor() {
    let spd = SharedPayloadDescriptor {
        region_id: 42,
        payload_len: 1024,
        payload_hash: ContentHash::compute(b"test"),
    };
    let v: serde_json::Value = serde_json::to_value(&spd).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["region_id", "payload_len", "payload_hash"] {
        assert!(
            obj.contains_key(key),
            "SharedPayloadDescriptor missing field: {key}"
        );
    }
}

// ===========================================================================
// 13) JSON field-name stability — SessionHandshake
// ===========================================================================

#[test]
fn json_fields_session_handshake() {
    let sh = SessionHandshake {
        session_id: "s1".into(),
        extension_id: "ext1".into(),
        host_id: "host1".into(),
        extension_nonce: 123,
        host_nonce: 456,
        timestamp_ticks: 1000,
        trace_id: "t1".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&sh).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "session_id",
        "extension_id",
        "host_id",
        "extension_nonce",
        "host_nonce",
        "timestamp_ticks",
        "trace_id",
    ] {
        assert!(
            obj.contains_key(key),
            "SessionHandshake missing field: {key}"
        );
    }
}

// ===========================================================================
// 14) Serde roundtrips — additional types
// ===========================================================================

#[test]
fn serde_roundtrip_backpressure_signal() {
    let bs = BackpressureSignal {
        pending_messages: 50,
        limit: 100,
    };
    let json = serde_json::to_string(&bs).unwrap();
    let rt: BackpressureSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(bs, rt);
}

#[test]
fn serde_roundtrip_shared_payload_descriptor() {
    let spd = SharedPayloadDescriptor {
        region_id: 7,
        payload_len: 512,
        payload_hash: ContentHash::compute(b"payload"),
    };
    let json = serde_json::to_string(&spd).unwrap();
    let rt: SharedPayloadDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(spd, rt);
}

#[test]
fn serde_roundtrip_session_handshake() {
    let sh = SessionHandshake {
        session_id: "sess-1".into(),
        extension_id: "ext-1".into(),
        host_id: "host-1".into(),
        extension_nonce: 111,
        host_nonce: 222,
        timestamp_ticks: 5000,
        trace_id: "trace-1".into(),
    };
    let json = serde_json::to_string(&sh).unwrap();
    let rt: SessionHandshake = serde_json::from_str(&json).unwrap();
    assert_eq!(sh, rt);
}

#[test]
fn serde_roundtrip_replay_drop_reason() {
    for r in [
        ReplayDropReason::Replay,
        ReplayDropReason::Duplicate,
        ReplayDropReason::OutOfOrder,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let rt: ReplayDropReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, rt);
    }
}

// ===========================================================================
// 15) AeadAlgorithm — nonce_len exact values
// ===========================================================================

#[test]
fn aead_algorithm_nonce_len_chacha() {
    assert_eq!(AeadAlgorithm::ChaCha20Poly1305.nonce_len(), 12);
}

#[test]
fn aead_algorithm_nonce_len_aes() {
    assert_eq!(AeadAlgorithm::Aes256Gcm.nonce_len(), 12);
}

#[test]
fn aead_algorithm_nonce_len_xchacha() {
    assert_eq!(AeadAlgorithm::XChaCha20Poly1305.nonce_len(), 24);
}

// ===========================================================================
// 16) AeadAlgorithm — max_messages_per_key exact values
// ===========================================================================

#[test]
fn aead_algorithm_max_messages_aes() {
    assert_eq!(AeadAlgorithm::Aes256Gcm.max_messages_per_key(), 1u64 << 32);
}

#[test]
fn aead_algorithm_max_messages_chacha() {
    assert_eq!(
        AeadAlgorithm::ChaCha20Poly1305.max_messages_per_key(),
        u64::MAX
    );
}

#[test]
fn aead_algorithm_max_messages_xchacha() {
    assert_eq!(
        AeadAlgorithm::XChaCha20Poly1305.max_messages_per_key(),
        u64::MAX
    );
}

// ===========================================================================
// 17) SessionChannelError — Display exact substring coverage
// ===========================================================================

#[test]
fn session_channel_error_display_invalid_identity() {
    let err = SessionChannelError::InvalidIdentity {
        field: "host_id".into(),
    };
    let s = err.to_string();
    assert!(s.contains("invalid identity field"), "got: {s}");
    assert!(s.contains("host_id"), "got: {s}");
}

#[test]
fn session_channel_error_display_nonce_exhausted() {
    let err = SessionChannelError::NonceExhausted {
        sequence: 999,
        limit: 500,
        algorithm: AeadAlgorithm::Aes256Gcm,
    };
    let s = err.to_string();
    assert!(s.contains("nonce budget exhausted"), "got: {s}");
    assert!(s.contains("999"), "got: {s}");
    assert!(s.contains("500"), "got: {s}");
}

#[test]
fn session_channel_error_display_backpressure_includes_values() {
    let err = SessionChannelError::Backpressure {
        session_id: "bp-sess".into(),
        pending: 42,
        limit: 10,
    };
    let s = err.to_string();
    assert!(s.contains("bp-sess"), "got: {s}");
    assert!(s.contains("pending=42"), "got: {s}");
    assert!(s.contains("limit=10"), "got: {s}");
}

// ===========================================================================
// 18) SessionChannelError — serde roundtrip for all variants
// ===========================================================================

#[test]
fn session_channel_error_serde_roundtrip_all_variants() {
    let variants: Vec<SessionChannelError> = vec![
        SessionChannelError::InvalidIdentity {
            field: "session_id".into(),
        },
        SessionChannelError::InvalidHandshake {
            detail: "bad nonce".into(),
        },
        SessionChannelError::SessionAlreadyExists {
            session_id: "dup".into(),
        },
        SessionChannelError::SessionNotFound {
            session_id: "missing".into(),
        },
        SessionChannelError::SessionNotEstablished {
            session_id: "s".into(),
            state: SessionState::Expired,
        },
        SessionChannelError::SessionExpired {
            session_id: "s".into(),
            reason: "timeout".into(),
        },
        SessionChannelError::Backpressure {
            session_id: "s".into(),
            pending: 50,
            limit: 25,
        },
        SessionChannelError::NoMessageAvailable {
            session_id: "s".into(),
        },
        SessionChannelError::SessionBindingMismatch {
            expected_session_id: "a".into(),
            actual_session_id: "b".into(),
        },
        SessionChannelError::MacMismatch {
            session_id: "s".into(),
            sequence: 7,
        },
        SessionChannelError::ReplayDetected {
            session_id: "s".into(),
            sequence: 3,
            last_seen: 5,
        },
        SessionChannelError::OutOfOrderDetected {
            session_id: "s".into(),
            sequence: 10,
            expected_min: 4,
        },
        SessionChannelError::NonceExhausted {
            sequence: 100,
            limit: 50,
            algorithm: AeadAlgorithm::XChaCha20Poly1305,
        },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let restored: SessionChannelError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "roundtrip failed for {err:?}");
    }
}

// ===========================================================================
// 19) SessionChannelError — Debug strings are all distinct
// ===========================================================================

#[test]
fn session_channel_error_debug_all_distinct() {
    let variants: Vec<SessionChannelError> = vec![
        SessionChannelError::InvalidIdentity { field: "f".into() },
        SessionChannelError::InvalidHandshake { detail: "d".into() },
        SessionChannelError::SessionAlreadyExists {
            session_id: "s".into(),
        },
        SessionChannelError::SessionNotFound {
            session_id: "s".into(),
        },
        SessionChannelError::SessionNotEstablished {
            session_id: "s".into(),
            state: SessionState::Init,
        },
        SessionChannelError::SessionExpired {
            session_id: "s".into(),
            reason: "r".into(),
        },
        SessionChannelError::Backpressure {
            session_id: "s".into(),
            pending: 1,
            limit: 2,
        },
        SessionChannelError::NoMessageAvailable {
            session_id: "s".into(),
        },
        SessionChannelError::SessionBindingMismatch {
            expected_session_id: "a".into(),
            actual_session_id: "b".into(),
        },
        SessionChannelError::MacMismatch {
            session_id: "s".into(),
            sequence: 1,
        },
        SessionChannelError::ReplayDetected {
            session_id: "s".into(),
            sequence: 1,
            last_seen: 2,
        },
        SessionChannelError::OutOfOrderDetected {
            session_id: "s".into(),
            sequence: 5,
            expected_min: 3,
        },
        SessionChannelError::NonceExhausted {
            sequence: 10,
            limit: 5,
            algorithm: AeadAlgorithm::Aes256Gcm,
        },
    ];
    let debug_strings: BTreeSet<String> = variants.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debug_strings.len(), variants.len());
}

// ===========================================================================
// 20) ChannelPayload — serde roundtrip and Debug distinctness
// ===========================================================================

#[test]
fn channel_payload_serde_roundtrip_all_variants() {
    let payloads = vec![
        ChannelPayload::Inline(vec![0xDE, 0xAD]),
        ChannelPayload::Shared(SharedPayloadDescriptor {
            region_id: 99,
            payload_len: 2048,
            payload_hash: ContentHash::compute(b"shared-data"),
        }),
        ChannelPayload::Backpressure(BackpressureSignal {
            pending_messages: 30,
            limit: 64,
        }),
    ];
    for p in &payloads {
        let json = serde_json::to_string(p).unwrap();
        let restored: ChannelPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, restored);
    }
}

#[test]
fn channel_payload_debug_all_distinct() {
    let payloads = vec![
        ChannelPayload::Inline(vec![1]),
        ChannelPayload::Shared(SharedPayloadDescriptor {
            region_id: 1,
            payload_len: 1,
            payload_hash: ContentHash::compute(b"x"),
        }),
        ChannelPayload::Backpressure(BackpressureSignal {
            pending_messages: 1,
            limit: 1,
        }),
    ];
    let debug_strings: BTreeSet<String> = payloads.iter().map(|p| format!("{p:?}")).collect();
    assert_eq!(debug_strings.len(), 3);
}

// ===========================================================================
// 21) HostcallEnvelope — JSON field stability
// ===========================================================================

#[test]
fn json_fields_hostcall_envelope() {
    let env = HostcallEnvelope {
        session_id: "s".into(),
        extension_id: "e".into(),
        host_id: "h".into(),
        sequence: 1,
        payload: ChannelPayload::Inline(vec![]),
        mac: AuthenticityHash::compute_keyed(b"k", b"v"),
        trace_id: "t".into(),
        sent_at_tick: 100,
    };
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "session_id",
        "extension_id",
        "host_id",
        "sequence",
        "payload",
        "mac",
        "trace_id",
        "sent_at_tick",
    ] {
        assert!(
            obj.contains_key(key),
            "HostcallEnvelope missing field: {key}"
        );
    }
}

// ===========================================================================
// 22) SessionChannelEvent — JSON field stability
// ===========================================================================

#[test]
fn json_fields_session_channel_event() {
    let evt = SessionChannelEvent {
        trace_id: "t".into(),
        decision_id: Some("d".into()),
        policy_id: Some("p".into()),
        component: "session_hostcall_channel".into(),
        event: "test".into(),
        outcome: "ok".into(),
        error_code: None,
        session_id: "s".into(),
        extension_id: "e".into(),
        host_id: "h".into(),
        sequence: Some(1),
        expected_min_seq: None,
        received_seq: None,
        drop_reason: None,
        source_principal: None,
        timestamp_ticks: 500,
    };
    let v: serde_json::Value = serde_json::to_value(&evt).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "session_id",
        "extension_id",
        "host_id",
        "sequence",
        "expected_min_seq",
        "received_seq",
        "drop_reason",
        "source_principal",
        "timestamp_ticks",
    ] {
        assert!(
            obj.contains_key(key),
            "SessionChannelEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 23) SessionHandle — clone, eq, serde roundtrip
// ===========================================================================

#[test]
fn session_handle_clone_eq_serde() {
    let handle = SessionHandle {
        session_id: "my-session".into(),
    };
    let cloned = handle.clone();
    assert_eq!(handle, cloned);

    let json = serde_json::to_string(&handle).unwrap();
    let restored: SessionHandle = serde_json::from_str(&json).unwrap();
    assert_eq!(handle, restored);

    let v: serde_json::Value = serde_json::to_value(&handle).unwrap();
    assert!(v.as_object().unwrap().contains_key("session_id"));
}

// ===========================================================================
// 24) DeterministicNonce — serde roundtrip and as_bytes consistency
// ===========================================================================

#[test]
fn deterministic_nonce_serde_roundtrip_and_len() {
    let key = [0x42; 32];
    let nonce = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        1,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    assert_eq!(nonce.as_bytes().len(), 12);

    let json = serde_json::to_string(&nonce).unwrap();
    let restored: DeterministicNonce = serde_json::from_str(&json).unwrap();
    assert_eq!(nonce.as_bytes(), restored.as_bytes());
}

// ===========================================================================
// 25) build_aead_associated_data — determinism and uniqueness
// ===========================================================================

#[test]
fn aead_associated_data_deterministic_and_unique() {
    let ad1 = build_aead_associated_data("session-A", "invoke", 0);
    let ad2 = build_aead_associated_data("session-A", "invoke", 0);
    assert_eq!(ad1, ad2, "same inputs must produce identical output");

    let ad_diff_session = build_aead_associated_data("session-B", "invoke", 0);
    assert_ne!(ad1, ad_diff_session, "different session_id must differ");

    let ad_diff_type = build_aead_associated_data("session-A", "callback", 0);
    assert_ne!(ad1, ad_diff_type, "different message_type must differ");

    let ad_diff_flags = build_aead_associated_data("session-A", "invoke", 1);
    assert_ne!(ad1, ad_diff_flags, "different flags must differ");
}

// ===========================================================================
// 26) derive_deterministic_aead_nonce — XChaCha vs ChaCha produce
//     different length nonces
// ===========================================================================

#[test]
fn deterministic_nonce_algorithm_produces_correct_lengths() {
    let key = [0x77; 32];
    let chacha = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        5,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    let aes = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        5,
        AeadAlgorithm::Aes256Gcm,
    )
    .unwrap();
    let xchacha = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        5,
        AeadAlgorithm::XChaCha20Poly1305,
    )
    .unwrap();

    assert_eq!(chacha.as_bytes().len(), 12);
    assert_eq!(aes.as_bytes().len(), 12);
    assert_eq!(xchacha.as_bytes().len(), 24);

    // Same key/direction/sequence but different algorithms should produce
    // different nonce bytes (at least for the 12-byte prefix).
    assert_ne!(
        chacha.as_bytes(),
        aes.as_bytes(),
        "ChaCha and AES nonces should differ"
    );
}

// ===========================================================================
// 27) SessionHostcallChannel — full create-send-receive-close lifecycle
// ===========================================================================

fn make_signing_key(byte: u8) -> SigningKey {
    SigningKey::from_bytes([byte; 32])
}

fn make_handshake(session_id: &str, tick: u64) -> SessionHandshake {
    SessionHandshake {
        session_id: session_id.into(),
        extension_id: "ext-integ".into(),
        host_id: "host-integ".into(),
        extension_nonce: 100,
        host_nonce: 200,
        timestamp_ticks: tick,
        trace_id: "trace-integ".into(),
    }
}

#[test]
fn full_lifecycle_create_send_receive_close() {
    let mut ch = SessionHostcallChannel::new();
    let handle = ch
        .create_session(
            make_handshake("lifecycle-1", 10),
            &make_signing_key(0xAA),
            &make_signing_key(0xBB),
            SessionConfig::default(),
        )
        .unwrap();

    assert_eq!(ch.session_state(&handle), Some(SessionState::Established));
    assert_eq!(ch.queue_len(&handle), Some(0));

    let seq = ch
        .send(&handle, b"hello".to_vec(), "t1", 11, None, None)
        .unwrap();
    assert_eq!(seq, 1);
    assert_eq!(ch.queue_len(&handle), Some(1));

    let payload = ch.receive(&handle, "t2", 12, None, None).unwrap();
    assert_eq!(payload, ChannelPayload::Inline(b"hello".to_vec()));
    assert_eq!(ch.queue_len(&handle), Some(0));

    ch.close_session(&handle, "t3", 13, None, None).unwrap();
    assert_eq!(ch.session_state(&handle), Some(SessionState::Closed));
}

// ===========================================================================
// 28) SessionHostcallChannel — drain_events returns and clears
// ===========================================================================

#[test]
fn drain_events_returns_accumulated_then_empty() {
    let mut ch = SessionHostcallChannel::new();
    let handle = ch
        .create_session(
            make_handshake("drain-evt", 10),
            &make_signing_key(0xCC),
            &make_signing_key(0xDD),
            SessionConfig::default(),
        )
        .unwrap();
    ch.send(&handle, b"msg".to_vec(), "t1", 11, None, None)
        .unwrap();

    let events = ch.drain_events();
    assert!(events.len() >= 2, "should have create + send events");
    assert!(
        events.iter().any(|e| e.event == "session_created"),
        "missing session_created event"
    );
    assert!(
        events.iter().any(|e| e.event == "message_sent"),
        "missing message_sent event"
    );

    let second = ch.drain_events();
    assert!(second.is_empty(), "drain should clear event buffer");
}

// ===========================================================================
// 29) SessionConfig — serde roundtrip with custom values
// ===========================================================================

#[test]
fn session_config_custom_serde_roundtrip() {
    let cfg = SessionConfig {
        max_lifetime_ticks: 5_000,
        max_messages: 500,
        max_buffered_messages: 32,
        sequence_policy: SequencePolicy::Strict,
        replay_drop_threshold: 3,
        replay_drop_window_ticks: 200,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: SessionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
    assert_eq!(restored.sequence_policy, SequencePolicy::Strict);
}

// ===========================================================================
// 30) BackpressureSignal — clone equality and zero edge case
// ===========================================================================

#[test]
fn backpressure_signal_clone_eq_and_zero_edge() {
    let zero = BackpressureSignal {
        pending_messages: 0,
        limit: 0,
    };
    let cloned = zero.clone();
    assert_eq!(zero, cloned);

    let max = BackpressureSignal {
        pending_messages: usize::MAX,
        limit: usize::MAX,
    };
    let json = serde_json::to_string(&max).unwrap();
    let restored: BackpressureSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(max, restored);
}

// ===========================================================================
// 31) AeadAlgorithm — nonce exhaustion at exact boundary
// ===========================================================================

#[test]
fn aes_nonce_budget_exact_boundary() {
    let key = [0x33; 32];
    // Sequence just below AES limit should succeed
    let just_below = (1u64 << 32) - 1;
    let ok = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        just_below,
        AeadAlgorithm::Aes256Gcm,
    );
    assert!(ok.is_ok(), "sequence at limit-1 should succeed");

    // Sequence at the exact limit should fail
    let at_limit = 1u64 << 32;
    let err = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        at_limit,
        AeadAlgorithm::Aes256Gcm,
    );
    assert!(err.is_err(), "sequence at limit should fail");
    let e = err.unwrap_err();
    assert!(
        matches!(e, SessionChannelError::NonceExhausted { .. }),
        "expected NonceExhausted, got {e:?}"
    );
}

// ===========================================================================
// 32) SessionChannelEvent — serde roundtrip with all optional fields
// ===========================================================================

#[test]
fn session_channel_event_serde_roundtrip_full_and_minimal() {
    let full = SessionChannelEvent {
        trace_id: "t".into(),
        decision_id: Some("dec".into()),
        policy_id: Some("pol".into()),
        component: "session_hostcall_channel".into(),
        event: "message_sent".into(),
        outcome: "ok".into(),
        error_code: Some("FE-5003".into()),
        session_id: "s".into(),
        extension_id: "e".into(),
        host_id: "h".into(),
        sequence: Some(42),
        expected_min_seq: Some(10),
        received_seq: Some(42),
        drop_reason: Some("replay".into()),
        source_principal: Some("ext-1".into()),
        timestamp_ticks: 9999,
    };
    let json_full = serde_json::to_string(&full).unwrap();
    let restored_full: SessionChannelEvent = serde_json::from_str(&json_full).unwrap();
    assert_eq!(full, restored_full);

    let minimal = SessionChannelEvent {
        trace_id: "t".into(),
        decision_id: None,
        policy_id: None,
        component: "c".into(),
        event: "e".into(),
        outcome: "ok".into(),
        error_code: None,
        session_id: "s".into(),
        extension_id: "ext".into(),
        host_id: "host".into(),
        sequence: None,
        expected_min_seq: None,
        received_seq: None,
        drop_reason: None,
        source_principal: None,
        timestamp_ticks: 0,
    };
    let json_min = serde_json::to_string(&minimal).unwrap();
    let restored_min: SessionChannelEvent = serde_json::from_str(&json_min).unwrap();
    assert_eq!(minimal, restored_min);
}
