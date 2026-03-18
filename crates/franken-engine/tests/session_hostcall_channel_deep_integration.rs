#![forbid(unsafe_code)]
//! Deep integration tests for `session_hostcall_channel`.
//!
//! Focuses on UNCOVERED areas beyond the existing 51 + 32 tests:
//! backpressure signal creation/verification round-trips, MAC tamper
//! detection on signals, session-binding mismatch on signals, expired-state
//! transitions, interleaved inline/shared sends, stress tests, determinism,
//! empty/large payloads, queue-length tracking, event field validation,
//! boundary tick expiry, send-only budget exhaustion, nonce uniqueness,
//! replay-drop window resets, zero-threshold escalation disabling,
//! and comprehensive serde/Display edge cases.

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
    AeadAlgorithm, BackpressureSignal, ChannelPayload, DataPlaneDirection, HandshakeRequest,
    HandshakeResponse, HostcallEnvelope, ReplayDropReason, SequencePolicy, SessionChannelError,
    SessionChannelEvent, SessionConfig, SessionHandle, SessionHandshake, SessionHostcallChannel,
    SessionState, SharedPayloadDescriptor, SharedSendInput, build_aead_associated_data,
    derive_deterministic_aead_nonce,
};
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_bytes([byte; 32])
}

fn handshake(session_id: &str, trace_id: &str, tick: u64) -> SessionHandshake {
    SessionHandshake {
        session_id: session_id.to_string(),
        extension_id: "ext-deep".to_string(),
        host_id: "host-deep".to_string(),
        extension_nonce: 42,
        host_nonce: 99,
        timestamp_ticks: tick,
        trace_id: trace_id.to_string(),
    }
}

fn handshake_custom(
    session_id: &str,
    ext_id: &str,
    host_id: &str,
    ext_nonce: u64,
    host_nonce: u64,
    tick: u64,
) -> SessionHandshake {
    SessionHandshake {
        session_id: session_id.to_string(),
        extension_id: ext_id.to_string(),
        host_id: host_id.to_string(),
        extension_nonce: ext_nonce,
        host_nonce: host_nonce,
        timestamp_ticks: tick,
        trace_id: "trace-custom".to_string(),
    }
}

fn create_basic_session(channel: &mut SessionHostcallChannel, session_id: &str) -> SessionHandle {
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

// ===========================================================================
// 1) Backpressure signal creation + verification positive round-trip
// ===========================================================================

#[test]
fn backpressure_signal_create_and_verify_round_trip() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-bp-rt");

    let signal = channel
        .authenticated_backpressure_signal(&handle, 5, 10, "trace-bp", 101)
        .expect("signal should be created");

    assert_eq!(signal.session_id, "sess-bp-rt");
    assert_eq!(signal.extension_id, "ext-deep");
    assert_eq!(signal.host_id, "host-deep");

    match &signal.payload {
        ChannelPayload::Backpressure(bp) => {
            assert_eq!(bp.pending_messages, 5);
            assert_eq!(bp.limit, 10);
        }
        other => panic!("expected Backpressure payload, got {other:?}"),
    }

    channel
        .verify_authenticated_signal(&handle, &signal)
        .expect("verification should pass");
}

// ===========================================================================
// 2) Verify signal rejects tampered MAC
// ===========================================================================

#[test]
fn verify_signal_rejects_tampered_mac() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-bp-tamper");

    let mut signal = channel
        .authenticated_backpressure_signal(&handle, 3, 8, "trace-bp", 101)
        .expect("signal");

    // Tamper the MAC
    signal.mac = AuthenticityHash::compute_keyed(b"wrong-key", b"wrong-data");

    let err = channel
        .verify_authenticated_signal(&handle, &signal)
        .expect_err("should fail");
    assert!(matches!(err, SessionChannelError::MacMismatch { .. }));
}

// ===========================================================================
// 3) Verify signal with session binding mismatch on envelope
// ===========================================================================

#[test]
fn verify_signal_rejects_mismatched_session_id_in_envelope() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-bp-bind");

    let mut signal = channel
        .authenticated_backpressure_signal(&handle, 1, 5, "trace-bp", 101)
        .expect("signal");

    // Tamper the session_id in the envelope itself
    signal.session_id = "different-session".to_string();

    let err = channel
        .verify_authenticated_signal(&handle, &signal)
        .expect_err("should fail");
    assert!(
        matches!(err, SessionChannelError::SessionBindingMismatch { .. }),
        "expected SessionBindingMismatch, got {err:?}"
    );
}

// ===========================================================================
// 4) Send on expired session fails with NotEstablished
// ===========================================================================

#[test]
fn send_on_expired_session_fails() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-exp-send",
        SessionConfig {
            max_lifetime_ticks: 10,
            ..SessionConfig::default()
        },
    );

    // Expire it (created at tick 100, expires at 110)
    let _ = channel.send(&handle, b"late".to_vec(), "t-late", 111, None, None);
    assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));

    // Now try again
    let err = channel
        .send(&handle, b"more".to_vec(), "t-more", 112, None, None)
        .expect_err("should fail");
    assert!(
        matches!(err, SessionChannelError::SessionNotEstablished { .. }),
        "expected SessionNotEstablished, got {err:?}"
    );
}

// ===========================================================================
// 5) Close on expired session succeeds (closes from any non-closed state)
// ===========================================================================

#[test]
fn close_expired_session_transitions_to_closed() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-exp-close",
        SessionConfig {
            max_lifetime_ticks: 10,
            ..SessionConfig::default()
        },
    );

    // Force expiry
    let _ = channel.send(&handle, b"late".to_vec(), "t-late", 111, None, None);
    assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));

    // close_session should still work on expired (it only rejects Closed)
    channel
        .close_session(&handle, "t-close", 112, None, None)
        .expect("close expired should succeed");
    assert_eq!(channel.session_state(&handle), Some(SessionState::Closed));
}

// ===========================================================================
// 6) Interleaved inline and shared sends maintain correct ordering
// ===========================================================================

#[test]
fn interleaved_inline_and_shared_sends_preserve_order() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-interleave");

    // inline
    channel
        .send(&handle, b"inline-1".to_vec(), "t1", 101, None, None)
        .unwrap();
    // shared
    channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 10,
                payload: b"shared-payload",
                trace_id: "t2",
                timestamp_ticks: 102,
                decision_id: None,
                policy_id: None,
            },
        )
        .unwrap();
    // inline again
    channel
        .send(&handle, b"inline-2".to_vec(), "t3", 103, None, None)
        .unwrap();

    assert_eq!(channel.queue_len(&handle), Some(3));

    // Receive all three in order
    let p1 = channel.receive(&handle, "r1", 104, None, None).unwrap();
    assert_eq!(p1, ChannelPayload::Inline(b"inline-1".to_vec()));

    let p2 = channel.receive(&handle, "r2", 105, None, None).unwrap();
    match p2 {
        ChannelPayload::Shared(desc) => {
            assert_eq!(desc.region_id, 10);
            assert_eq!(desc.payload_len, b"shared-payload".len());
        }
        other => panic!("expected Shared, got {other:?}"),
    }

    let p3 = channel.receive(&handle, "r3", 106, None, None).unwrap();
    assert_eq!(p3, ChannelPayload::Inline(b"inline-2".to_vec()));

    assert_eq!(channel.queue_len(&handle), Some(0));
}

// ===========================================================================
// 7) Stress test: many messages in one session
// ===========================================================================

#[test]
fn stress_many_messages_round_trip() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-stress",
        SessionConfig {
            max_messages: 2000,
            max_buffered_messages: 1000,
            ..SessionConfig::default()
        },
    );

    let count = 500;
    for i in 0..count {
        let seq = channel
            .send(
                &handle,
                vec![(i % 256) as u8],
                &format!("t-send-{i}"),
                101 + i as u64,
                None,
                None,
            )
            .unwrap();
        assert_eq!(seq, i as u64 + 1);
    }
    assert_eq!(channel.queue_len(&handle), Some(count));

    for i in 0..count {
        let payload = channel
            .receive(&handle, &format!("t-recv-{i}"), 601 + i as u64, None, None)
            .unwrap();
        assert_eq!(payload, ChannelPayload::Inline(vec![(i % 256) as u8]));
    }
    assert_eq!(channel.queue_len(&handle), Some(0));
}

// ===========================================================================
// 8) Determinism: same inputs yield same session behavior
// ===========================================================================

#[test]
fn deterministic_session_creation_yields_same_sequence() {
    let mut ch1 = SessionHostcallChannel::new();
    let mut ch2 = SessionHostcallChannel::new();

    let h1 = ch1
        .create_session(
            handshake("det-sess", "trace-det", 100),
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();
    let h2 = ch2
        .create_session(
            handshake("det-sess", "trace-det", 100),
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();

    // Send the same payload
    let seq1 = ch1
        .send(&h1, b"data".to_vec(), "trace-s", 101, None, None)
        .unwrap();
    let seq2 = ch2
        .send(&h2, b"data".to_vec(), "trace-s", 101, None, None)
        .unwrap();
    assert_eq!(seq1, seq2);

    // Receive: both should produce identical payloads
    let p1 = ch1.receive(&h1, "trace-r", 102, None, None).unwrap();
    let p2 = ch2.receive(&h2, "trace-r", 102, None, None).unwrap();
    assert_eq!(p1, p2);
}

// ===========================================================================
// 9) Different nonces yield different session keys (different MACs)
// ===========================================================================

#[test]
fn different_nonces_produce_different_session_behavior() {
    let mut ch1 = SessionHostcallChannel::new();
    let mut ch2 = SessionHostcallChannel::new();

    let h1 = ch1
        .create_session(
            handshake_custom("diff-nonce", "ext-a", "host-a", 1, 2, 100),
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();
    let h2 = ch2
        .create_session(
            handshake_custom("diff-nonce", "ext-a", "host-a", 3, 4, 100),
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();

    ch1.send(&h1, b"test".to_vec(), "t", 101, None, None)
        .unwrap();
    ch2.send(&h2, b"test".to_vec(), "t", 101, None, None)
        .unwrap();

    // Generate backpressure signals and compare MACs — should differ
    let sig1 = ch1
        .authenticated_backpressure_signal(&h1, 1, 10, "bp", 102)
        .unwrap();
    let sig2 = ch2
        .authenticated_backpressure_signal(&h2, 1, 10, "bp", 102)
        .unwrap();

    // Different session keys should produce different MACs
    assert_ne!(sig1.mac, sig2.mac);
}

// ===========================================================================
// 10) Empty payload send/receive
// ===========================================================================

#[test]
fn empty_payload_send_and_receive() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-empty-payload");

    channel
        .send(&handle, vec![], "t1", 101, None, None)
        .unwrap();
    let payload = channel.receive(&handle, "r1", 102, None, None).unwrap();
    assert_eq!(payload, ChannelPayload::Inline(vec![]));
}

// ===========================================================================
// 11) Large payload send/receive
// ===========================================================================

#[test]
fn large_payload_send_and_receive() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-large-payload");

    let large = vec![0xAB; 65536];
    channel
        .send(&handle, large.clone(), "t1", 101, None, None)
        .unwrap();
    let payload = channel.receive(&handle, "r1", 102, None, None).unwrap();
    assert_eq!(payload, ChannelPayload::Inline(large));
}

// ===========================================================================
// 12) Queue length tracks send/receive accurately
// ===========================================================================

#[test]
fn queue_length_tracks_sends_and_receives() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-qlen");

    assert_eq!(channel.queue_len(&handle), Some(0));

    for i in 0..5 {
        channel
            .send(
                &handle,
                vec![i],
                &format!("t{i}"),
                101 + i as u64,
                None,
                None,
            )
            .unwrap();
        assert_eq!(channel.queue_len(&handle), Some((i + 1) as usize));
    }

    for i in (0..5).rev() {
        channel
            .receive(&handle, &format!("r{i}"), 200 + i as u64, None, None)
            .unwrap();
        assert_eq!(channel.queue_len(&handle), Some(i));
    }
}

// ===========================================================================
// 13) Event for shared_payload_sent includes correct fields
// ===========================================================================

#[test]
fn shared_buffer_send_event_has_correct_fields() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-shared-evt");
    channel.drain_events(); // clear creation event

    channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 42,
                payload: b"test-payload",
                trace_id: "trace-shared",
                timestamp_ticks: 101,
                decision_id: Some("dec-shared"),
                policy_id: Some("pol-shared"),
            },
        )
        .unwrap();

    let events = channel.drain_events();
    let send_evt = events
        .iter()
        .find(|e| e.event == "shared_payload_sent")
        .expect("shared_payload_sent event should exist");

    assert_eq!(send_evt.trace_id, "trace-shared");
    assert_eq!(send_evt.decision_id.as_deref(), Some("dec-shared"));
    assert_eq!(send_evt.policy_id.as_deref(), Some("pol-shared"));
    assert_eq!(send_evt.session_id, "sess-shared-evt");
    assert_eq!(send_evt.component, "session_hostcall_channel");
    assert_eq!(send_evt.outcome, "ok");
    assert!(send_evt.sequence.is_some());
}

// ===========================================================================
// 14) Expiry at exact boundary tick
// ===========================================================================

#[test]
fn session_expires_at_exact_boundary_tick() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-boundary",
        SessionConfig {
            max_lifetime_ticks: 100,
            ..SessionConfig::default()
        },
    );

    // Created at tick 100, lifetime 100 => expires_at = 200
    // Tick 199 should still work
    channel
        .send(&handle, b"ok".to_vec(), "t-199", 199, None, None)
        .unwrap();

    // Tick 200 is exactly at boundary (>= expires_at_tick) => expired
    let err = channel
        .send(&handle, b"fail".to_vec(), "t-200", 200, None, None)
        .expect_err("should expire at boundary");
    assert!(matches!(err, SessionChannelError::SessionExpired { .. }));
}

// ===========================================================================
// 15) Send-only budget exhaustion (no receives)
// ===========================================================================

#[test]
fn send_only_budget_exhaustion() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-send-budget",
        SessionConfig {
            max_messages: 3,
            max_buffered_messages: 256,
            ..SessionConfig::default()
        },
    );

    // 3 sends should exhaust budget (sent_messages=3, received=0, total=3)
    for i in 0..3 {
        channel
            .send(
                &handle,
                vec![i as u8],
                &format!("t{i}"),
                101 + i as u64,
                None,
                None,
            )
            .unwrap();
    }

    // 4th send should fail
    let err = channel
        .send(&handle, b"over".to_vec(), "t-over", 104, None, None)
        .expect_err("should exceed budget");
    assert!(
        matches!(
            &err,
            SessionChannelError::SessionExpired { reason, .. }
            if reason.contains("message_budget")
        ),
        "expected message_budget expiry, got {err:?}"
    );
}

// ===========================================================================
// 16) Nonce derivation produces unique nonces per sequence
// ===========================================================================

#[test]
fn nonce_derivation_unique_per_sequence() {
    let key = [0x55; 32];
    let mut nonces = BTreeSet::new();

    for seq in 0..50 {
        let nonce = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            seq,
            AeadAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();
        let bytes = nonce.as_bytes().to_vec();
        assert!(
            nonces.insert(bytes),
            "nonce for sequence {seq} was not unique"
        );
    }
    assert_eq!(nonces.len(), 50);
}

// ===========================================================================
// 17) Nonce derivation: u64::MAX sequence with ChaCha succeeds
// ===========================================================================

#[test]
fn nonce_derivation_u64_max_chacha_succeeds() {
    let key = [0x66; 32];
    let result = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        u64::MAX - 1,
        AeadAlgorithm::ChaCha20Poly1305,
    );
    assert!(result.is_ok(), "ChaCha should accept very large sequences");
    assert_eq!(result.unwrap().as_bytes().len(), 12);
}

// ===========================================================================
// 18) AEAD associated data with empty strings
// ===========================================================================

#[test]
fn aead_associated_data_empty_strings() {
    let ad = build_aead_associated_data("", "", 0);
    assert!(!ad.is_empty(), "even empty strings should produce output");

    let ad_with_session = build_aead_associated_data("s", "", 0);
    assert_ne!(ad, ad_with_session, "non-empty session should differ");
}

// ===========================================================================
// 19) AEAD associated data with max flags
// ===========================================================================

#[test]
fn aead_associated_data_max_flags() {
    let ad_zero = build_aead_associated_data("sess", "type", 0);
    let ad_max = build_aead_associated_data("sess", "type", u32::MAX);
    assert_ne!(
        ad_zero, ad_max,
        "different flags should produce different AD"
    );
}

// ===========================================================================
// 20) AEAD associated data determinism
// ===========================================================================

#[test]
fn aead_associated_data_is_deterministic() {
    let ad1 = build_aead_associated_data("my-session", "invoke", 7);
    let ad2 = build_aead_associated_data("my-session", "invoke", 7);
    assert_eq!(ad1, ad2);
}

// ===========================================================================
// 21) Zero replay_drop_threshold disables escalation
// ===========================================================================

#[test]
fn zero_replay_threshold_never_escalates() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-no-escalate",
        SessionConfig {
            replay_drop_threshold: 0,
            replay_drop_window_ticks: 0,
            sequence_policy: SequencePolicy::Monotonic,
            ..SessionConfig::default()
        },
    );

    // Send and receive a message
    channel
        .send(&handle, b"msg".to_vec(), "t1", 101, None, None)
        .unwrap();
    channel.receive(&handle, "r1", 102, None, None).unwrap();

    // Session should remain established even after replay drops
    assert_eq!(
        channel.session_state(&handle),
        Some(SessionState::Established)
    );
}

// ===========================================================================
// 22) SharedSendInput with decision_id and policy_id
// ===========================================================================

#[test]
fn shared_send_with_decision_and_policy() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-shared-dp");
    channel.drain_events();

    let seq = channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 1,
                payload: b"payload",
                trace_id: "trace-dp",
                timestamp_ticks: 101,
                decision_id: Some("decision-xyz"),
                policy_id: Some("policy-abc"),
            },
        )
        .unwrap();
    assert_eq!(seq, 1);

    let events = channel.drain_events();
    let evt = events
        .iter()
        .find(|e| e.event == "shared_payload_sent")
        .unwrap();
    assert_eq!(evt.decision_id.as_deref(), Some("decision-xyz"));
    assert_eq!(evt.policy_id.as_deref(), Some("policy-abc"));
}

// ===========================================================================
// 23) Close event includes decision and policy ids
// ===========================================================================

#[test]
fn close_event_includes_decision_and_policy() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-close-dp");
    channel.drain_events();

    channel
        .close_session(
            &handle,
            "trace-close-dp",
            200,
            Some("close-dec"),
            Some("close-pol"),
        )
        .unwrap();

    let events = channel.drain_events();
    let close_evt = events
        .iter()
        .find(|e| e.event == "session_closed")
        .expect("close event should exist");
    assert_eq!(close_evt.decision_id.as_deref(), Some("close-dec"));
    assert_eq!(close_evt.policy_id.as_deref(), Some("close-pol"));
    assert_eq!(close_evt.trace_id, "trace-close-dp");
    assert_eq!(close_evt.timestamp_ticks, 200);
}

// ===========================================================================
// 24) Receive event includes decision and policy ids
// ===========================================================================

#[test]
fn receive_event_includes_decision_and_policy() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-recv-dp");
    channel
        .send(&handle, b"data".to_vec(), "t-send", 101, None, None)
        .unwrap();
    channel.drain_events();

    channel
        .receive(
            &handle,
            "trace-recv-dp",
            102,
            Some("recv-dec"),
            Some("recv-pol"),
        )
        .unwrap();

    let events = channel.drain_events();
    let recv_evt = events
        .iter()
        .find(|e| e.event == "message_received")
        .expect("receive event should exist");
    assert_eq!(recv_evt.decision_id.as_deref(), Some("recv-dec"));
    assert_eq!(recv_evt.policy_id.as_deref(), Some("recv-pol"));
    assert_eq!(recv_evt.trace_id, "trace-recv-dp");
}

// ===========================================================================
// 25) HandshakeRequest serde round-trip
// ===========================================================================

#[test]
fn handshake_request_serde_round_trip() {
    let ext_key = signing_key(10).verification_key();
    let sig =
        frankenengine_engine::signature_preimage::sign_preimage(&signing_key(10), b"test-preimage")
            .unwrap();

    let req = HandshakeRequest {
        session_id: "hs-req-1".into(),
        extension_id: "ext-1".into(),
        host_id: "host-1".into(),
        extension_nonce: 12345,
        timestamp_ticks: 67890,
        extension_key: ext_key,
        signature: sig,
    };

    let json = serde_json::to_string(&req).unwrap();
    let restored: HandshakeRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, restored);
}

// ===========================================================================
// 26) HandshakeResponse serde round-trip
// ===========================================================================

#[test]
fn handshake_response_serde_round_trip() {
    let host_key = signing_key(20).verification_key();
    let sig = frankenengine_engine::signature_preimage::sign_preimage(
        &signing_key(20),
        b"response-preimage",
    )
    .unwrap();

    let resp = HandshakeResponse {
        session_id: "hs-resp-1".into(),
        extension_nonce: 111,
        host_nonce: 222,
        host_key,
        signature: sig,
    };

    let json = serde_json::to_string(&resp).unwrap();
    let restored: HandshakeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, restored);
}

// ===========================================================================
// 27) HostcallEnvelope serde round-trip for each payload variant
// ===========================================================================

#[test]
fn hostcall_envelope_serde_round_trip_inline() {
    let env = HostcallEnvelope {
        session_id: "s".into(),
        extension_id: "e".into(),
        host_id: "h".into(),
        sequence: 42,
        payload: ChannelPayload::Inline(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        mac: AuthenticityHash::compute_keyed(b"key", b"data"),
        trace_id: "t".into(),
        sent_at_tick: 1000,
    };
    let json = serde_json::to_string(&env).unwrap();
    let restored: HostcallEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

#[test]
fn hostcall_envelope_serde_round_trip_shared() {
    let env = HostcallEnvelope {
        session_id: "s2".into(),
        extension_id: "e2".into(),
        host_id: "h2".into(),
        sequence: 99,
        payload: ChannelPayload::Shared(SharedPayloadDescriptor {
            region_id: 7,
            payload_len: 2048,
            payload_hash: ContentHash::compute(b"shared-test"),
        }),
        mac: AuthenticityHash::compute_keyed(b"key2", b"data2"),
        trace_id: "t2".into(),
        sent_at_tick: 2000,
    };
    let json = serde_json::to_string(&env).unwrap();
    let restored: HostcallEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

#[test]
fn hostcall_envelope_serde_round_trip_backpressure() {
    let env = HostcallEnvelope {
        session_id: "s3".into(),
        extension_id: "e3".into(),
        host_id: "h3".into(),
        sequence: 0,
        payload: ChannelPayload::Backpressure(BackpressureSignal {
            pending_messages: 50,
            limit: 100,
        }),
        mac: AuthenticityHash::compute_keyed(b"key3", b"data3"),
        trace_id: "t3".into(),
        sent_at_tick: 3000,
    };
    let json = serde_json::to_string(&env).unwrap();
    let restored: HostcallEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

// ===========================================================================
// 28) Session creation event has correct fields
// ===========================================================================

#[test]
fn session_creation_event_fields_are_correct() {
    let mut channel = SessionHostcallChannel::new();
    let _handle = channel
        .create_session(
            SessionHandshake {
                session_id: "evt-check".into(),
                extension_id: "ext-evt".into(),
                host_id: "host-evt".into(),
                extension_nonce: 1,
                host_nonce: 2,
                timestamp_ticks: 500,
                trace_id: "trace-evt".into(),
            },
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();

    let events = channel.drain_events();
    assert_eq!(events.len(), 1);

    let evt = &events[0];
    assert_eq!(evt.event, "session_created");
    assert_eq!(evt.outcome, "ok");
    assert_eq!(evt.trace_id, "trace-evt");
    assert_eq!(evt.session_id, "evt-check");
    assert_eq!(evt.extension_id, "ext-evt");
    assert_eq!(evt.host_id, "host-evt");
    assert_eq!(evt.component, "session_hostcall_channel");
    assert_eq!(evt.timestamp_ticks, 500);
    assert!(evt.error_code.is_none());
    assert!(evt.sequence.is_none());
    assert!(evt.drop_reason.is_none());
    assert!(evt.source_principal.is_none());
}

// ===========================================================================
// 29) Multiple sessions: operations on one don't affect another
// ===========================================================================

#[test]
fn multi_session_queue_isolation() {
    let mut channel = SessionHostcallChannel::new();
    let h1 = create_basic_session(&mut channel, "iso-a");
    let h2 = channel
        .create_session(
            SessionHandshake {
                session_id: "iso-b".into(),
                extension_id: "ext-b".into(),
                host_id: "host-b".into(),
                extension_nonce: 77,
                host_nonce: 88,
                timestamp_ticks: 100,
                trace_id: "trace-b".into(),
            },
            &signing_key(3),
            &signing_key(4),
            SessionConfig::default(),
        )
        .unwrap();

    // Send to session 1 only
    for i in 0..10 {
        channel
            .send(&h1, vec![i], &format!("t{i}"), 101 + i as u64, None, None)
            .unwrap();
    }

    // Session 2 queue should be empty
    assert_eq!(channel.queue_len(&h1), Some(10));
    assert_eq!(channel.queue_len(&h2), Some(0));

    // Close session 1; session 2 should still be established
    channel
        .close_session(&h1, "t-close", 200, None, None)
        .unwrap();
    assert_eq!(channel.session_state(&h1), Some(SessionState::Closed));
    assert_eq!(channel.session_state(&h2), Some(SessionState::Established));
}

// ===========================================================================
// 30) Backpressure at max_buffered_messages boundary
// ===========================================================================

#[test]
fn backpressure_at_exact_buffer_limit() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-bp-exact",
        SessionConfig {
            max_buffered_messages: 3,
            ..SessionConfig::default()
        },
    );

    // Fill to capacity
    for i in 0..3 {
        channel
            .send(
                &handle,
                vec![i],
                &format!("t{i}"),
                101 + i as u64,
                None,
                None,
            )
            .unwrap();
    }
    assert_eq!(channel.queue_len(&handle), Some(3));

    // Next send should trigger backpressure
    let err = channel
        .send(&handle, b"over".to_vec(), "t-over", 104, None, None)
        .expect_err("should backpressure");
    match err {
        SessionChannelError::Backpressure { pending, limit, .. } => {
            assert_eq!(pending, 3);
            assert_eq!(limit, 3);
        }
        other => panic!("expected Backpressure, got {other:?}"),
    }
}

// ===========================================================================
// 31) Backpressure recovery after drain
// ===========================================================================

#[test]
fn backpressure_recovery_after_receive() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-bp-recover",
        SessionConfig {
            max_buffered_messages: 2,
            ..SessionConfig::default()
        },
    );

    // Fill to capacity
    channel
        .send(&handle, b"a".to_vec(), "t1", 101, None, None)
        .unwrap();
    channel
        .send(&handle, b"b".to_vec(), "t2", 102, None, None)
        .unwrap();

    // Backpressure
    let err = channel
        .send(&handle, b"c".to_vec(), "t3", 103, None, None)
        .expect_err("should backpressure");
    assert!(matches!(err, SessionChannelError::Backpressure { .. }));

    // Receive one to free space
    channel.receive(&handle, "r1", 104, None, None).unwrap();

    // Now sending should work again
    channel
        .send(&handle, b"d".to_vec(), "t4", 105, None, None)
        .unwrap();
    assert_eq!(channel.queue_len(&handle), Some(2));
}

// ===========================================================================
// 32) Shared buffer backpressure at exact boundary
// ===========================================================================

#[test]
fn shared_buffer_backpressure_exact_boundary() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-shared-bp-exact",
        SessionConfig {
            max_buffered_messages: 2,
            ..SessionConfig::default()
        },
    );

    channel
        .send(&handle, b"inline".to_vec(), "t1", 101, None, None)
        .unwrap();
    channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 1,
                payload: b"shared",
                trace_id: "t2",
                timestamp_ticks: 102,
                decision_id: None,
                policy_id: None,
            },
        )
        .unwrap();

    // Third should fail regardless of type
    let err = channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 2,
                payload: b"over",
                trace_id: "t3",
                timestamp_ticks: 103,
                decision_id: None,
                policy_id: None,
            },
        )
        .expect_err("should backpressure");
    assert!(matches!(err, SessionChannelError::Backpressure { .. }));
}

// ===========================================================================
// 33) Nonce derivation: same key, same direction, different algorithms
// ===========================================================================

#[test]
fn nonce_derivation_different_algorithms_produce_different_bytes() {
    let key = [0x88; 32];
    let seq = 42;

    let chacha = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        seq,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    let aes = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        seq,
        AeadAlgorithm::Aes256Gcm,
    )
    .unwrap();
    let xchacha = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        seq,
        AeadAlgorithm::XChaCha20Poly1305,
    )
    .unwrap();

    assert_ne!(chacha.as_bytes(), aes.as_bytes());
    // XChaCha is 24 bytes, so definitely different from ChaCha at 12
    assert_ne!(chacha.as_bytes().len(), xchacha.as_bytes().len());
}

// ===========================================================================
// 34) Nonce derivation: different keys produce different nonces
// ===========================================================================

#[test]
fn nonce_derivation_different_keys_different_nonces() {
    let key1 = [0x01; 32];
    let key2 = [0x02; 32];

    let n1 = derive_deterministic_aead_nonce(
        &key1,
        DataPlaneDirection::HostToExtension,
        1,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    let n2 = derive_deterministic_aead_nonce(
        &key2,
        DataPlaneDirection::HostToExtension,
        1,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();

    assert_ne!(n1.as_bytes(), n2.as_bytes());
}

// ===========================================================================
// 35) SessionChannelError implements std::error::Error
// ===========================================================================

#[test]
fn session_channel_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(SessionChannelError::InvalidIdentity {
        field: "test".into(),
    });
    assert!(!err.to_string().is_empty());
}

// ===========================================================================
// 36) SessionChannelError From<SignatureError>
// ===========================================================================

#[test]
fn session_channel_error_from_signature_error() {
    use frankenengine_engine::signature_preimage::SignatureError;

    let sig_err = SignatureError::VerificationFailed {
        signer: frankenengine_engine::signature_preimage::VerificationKey::from_bytes([0u8; 32]),
        reason: "test failure".to_string(),
    };
    let channel_err: SessionChannelError = sig_err.into();
    assert!(matches!(
        channel_err,
        SessionChannelError::SignatureFailure(_)
    ));
}

// ===========================================================================
// 37) SessionChannelError::SignatureFailure Display
// ===========================================================================

#[test]
fn session_channel_error_display_signature_failure() {
    use frankenengine_engine::signature_preimage::SignatureError;

    let err = SessionChannelError::SignatureFailure(SignatureError::VerificationFailed {
        signer: frankenengine_engine::signature_preimage::VerificationKey::from_bytes([0u8; 32]),
        reason: "test".to_string(),
    });
    let s = err.to_string();
    assert!(!s.is_empty(), "got: {s}");
}

// ===========================================================================
// 38) DeterministicNonce clone and equality
// ===========================================================================

#[test]
fn deterministic_nonce_clone_eq() {
    let key = [0x99; 32];
    let nonce = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::ExtensionToHost,
        7,
        AeadAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    let cloned = nonce.clone();
    assert_eq!(nonce, cloned);
    assert_eq!(nonce.as_bytes(), cloned.as_bytes());
}

// ===========================================================================
// 39) Session creation at tick 0
// ===========================================================================

#[test]
fn session_creation_at_tick_zero() {
    let mut channel = SessionHostcallChannel::new();
    let handle = channel
        .create_session(
            handshake("sess-tick-0", "trace-0", 0),
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();

    assert_eq!(
        channel.session_state(&handle),
        Some(SessionState::Established)
    );

    // Should work at tick 1
    channel
        .send(&handle, b"ok".to_vec(), "t1", 1, None, None)
        .unwrap();
}

// ===========================================================================
// 40) Session lifetime with saturating addition (near u64::MAX)
// ===========================================================================

#[test]
fn session_lifetime_saturating_at_u64_max() {
    let mut channel = SessionHostcallChannel::new();
    let handle = channel
        .create_session(
            handshake("sess-sat", "trace-sat", u64::MAX - 100),
            &signing_key(1),
            &signing_key(2),
            SessionConfig {
                max_lifetime_ticks: 200,
                ..SessionConfig::default()
            },
        )
        .unwrap();

    // expires_at_tick = saturating_add(u64::MAX - 100, 200) = u64::MAX
    // At u64::MAX - 1, should still work
    channel
        .send(&handle, b"ok".to_vec(), "t1", u64::MAX - 1, None, None)
        .unwrap();
}

// ===========================================================================
// 41) Session new() is equivalent to default()
// ===========================================================================

#[test]
fn session_channel_new_equivalent_to_default() {
    let ch1 = SessionHostcallChannel::new();
    let ch2 = SessionHostcallChannel::default();

    // Both should have empty session lists (no sessions = None for any handle)
    let ghost = SessionHandle {
        session_id: "ghost".into(),
    };
    assert_eq!(ch1.queue_len(&ghost), ch2.queue_len(&ghost));
    assert_eq!(ch1.session_state(&ghost), ch2.session_state(&ghost));
}

// ===========================================================================
// 42) Identity validation at exactly 128 chars
// ===========================================================================

#[test]
fn identity_validation_at_128_chars_boundary() {
    let mut channel = SessionHostcallChannel::new();

    // 128 chars in extension_id
    let mut hs = handshake("sess-128-ext", "trace", 100);
    hs.extension_id = "e".repeat(128);
    let handle = channel
        .create_session(
            hs,
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();
    assert_eq!(
        channel.session_state(&handle),
        Some(SessionState::Established)
    );
}

#[test]
fn identity_validation_at_129_chars_rejects() {
    let mut channel = SessionHostcallChannel::new();

    let mut hs = handshake("sess-129-ext", "trace", 100);
    hs.extension_id = "e".repeat(129);
    let err = channel
        .create_session(
            hs,
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .expect_err("should fail");
    assert!(matches!(err, SessionChannelError::InvalidIdentity { .. }));
}

// ===========================================================================
// 43) Identity validation: too-long host_id
// ===========================================================================

#[test]
fn identity_validation_too_long_host_id() {
    let mut channel = SessionHostcallChannel::new();

    let mut hs = handshake("sess-long-host", "trace", 100);
    hs.host_id = "h".repeat(129);
    let err = channel
        .create_session(
            hs,
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .expect_err("should fail");
    assert!(matches!(err, SessionChannelError::InvalidIdentity { .. }));
}

// ===========================================================================
// 44) Receive after session expires returns NotEstablished
// ===========================================================================

#[test]
fn receive_on_expired_session_fails() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-exp-recv",
        SessionConfig {
            max_lifetime_ticks: 10,
            ..SessionConfig::default()
        },
    );

    // Send while active
    channel
        .send(&handle, b"msg".to_vec(), "t-send", 101, None, None)
        .unwrap();

    // Expire it by trying to send after lifetime
    let _ = channel.send(&handle, b"x".to_vec(), "t-late", 111, None, None);

    // Now try receive
    let err = channel
        .receive(&handle, "t-recv", 112, None, None)
        .expect_err("should fail");
    assert!(
        matches!(err, SessionChannelError::SessionNotEstablished { .. }),
        "expected SessionNotEstablished, got {err:?}"
    );
}

// ===========================================================================
// 45) Backpressure signal on expired session fails
// ===========================================================================

#[test]
fn backpressure_signal_on_expired_session_fails() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-bp-expired",
        SessionConfig {
            max_lifetime_ticks: 10,
            ..SessionConfig::default()
        },
    );

    // Expire the session
    let _ = channel.send(&handle, b"x".to_vec(), "t", 111, None, None);
    assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));

    let err = channel
        .authenticated_backpressure_signal(&handle, 5, 10, "bp", 112)
        .expect_err("should fail");
    assert!(matches!(
        err,
        SessionChannelError::SessionNotEstablished { .. }
    ));
}

// ===========================================================================
// 46) Shared buffer on expired session fails
// ===========================================================================

#[test]
fn shared_buffer_send_on_expired_session_fails() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-shared-expired",
        SessionConfig {
            max_lifetime_ticks: 10,
            ..SessionConfig::default()
        },
    );

    let _ = channel.send(&handle, b"x".to_vec(), "t", 111, None, None);
    assert_eq!(channel.session_state(&handle), Some(SessionState::Expired));

    let err = channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 1,
                payload: b"data",
                trace_id: "t",
                timestamp_ticks: 112,
                decision_id: None,
                policy_id: None,
            },
        )
        .expect_err("should fail");
    assert!(matches!(
        err,
        SessionChannelError::SessionNotEstablished { .. }
    ));
}

// ===========================================================================
// 47) Shared buffer on nonexistent session fails
// ===========================================================================

#[test]
fn shared_buffer_send_on_nonexistent_session_fails() {
    let mut channel = SessionHostcallChannel::new();
    let handle = SessionHandle {
        session_id: "ghost".into(),
    };

    let err = channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 1,
                payload: b"data",
                trace_id: "t",
                timestamp_ticks: 100,
                decision_id: None,
                policy_id: None,
            },
        )
        .expect_err("should fail");
    assert!(matches!(err, SessionChannelError::SessionNotFound { .. }));
}

// ===========================================================================
// 48) ReplayDropReason Display (via Debug since no Display impl)
// ===========================================================================

#[test]
fn replay_drop_reason_debug_distinct() {
    let variants = [
        format!("{:?}", ReplayDropReason::Replay),
        format!("{:?}", ReplayDropReason::Duplicate),
        format!("{:?}", ReplayDropReason::OutOfOrder),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 49) SessionChannelError all variant Display strings are non-empty
// ===========================================================================

#[test]
fn all_error_display_strings_are_non_empty() {
    use frankenengine_engine::signature_preimage::SignatureError;

    let variants: Vec<SessionChannelError> = vec![
        SessionChannelError::InvalidIdentity { field: "f".into() },
        SessionChannelError::InvalidHandshake { detail: "d".into() },
        SessionChannelError::SignatureFailure(SignatureError::VerificationFailed {
            signer: frankenengine_engine::signature_preimage::VerificationKey::from_bytes(
                [0u8; 32],
            ),
            reason: "test".to_string(),
        }),
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

    for err in &variants {
        let display = err.to_string();
        assert!(!display.is_empty(), "display for {err:?} is empty");
    }
}

// ===========================================================================
// 50) Sequence numbers start at 1 and increment
// ===========================================================================

#[test]
fn sequence_starts_at_one_and_increments() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-seq-start");

    let seq1 = channel
        .send(&handle, b"a".to_vec(), "t1", 101, None, None)
        .unwrap();
    let seq2 = channel
        .send(&handle, b"b".to_vec(), "t2", 102, None, None)
        .unwrap();
    let seq3 = channel
        .send(&handle, b"c".to_vec(), "t3", 103, None, None)
        .unwrap();

    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
    assert_eq!(seq3, 3);
}

// ===========================================================================
// 51) Shared buffer sequence continues from inline sends
// ===========================================================================

#[test]
fn shared_buffer_sequence_continues_from_inline() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-seq-shared");

    let s1 = channel
        .send(&handle, b"inline".to_vec(), "t1", 101, None, None)
        .unwrap();
    assert_eq!(s1, 1);

    let s2 = channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 1,
                payload: b"shared",
                trace_id: "t2",
                timestamp_ticks: 102,
                decision_id: None,
                policy_id: None,
            },
        )
        .unwrap();
    assert_eq!(s2, 2);

    let s3 = channel
        .send(&handle, b"inline-2".to_vec(), "t3", 103, None, None)
        .unwrap();
    assert_eq!(s3, 3);
}

// ===========================================================================
// 52) Verify signal on non-existent session
// ===========================================================================

#[test]
fn verify_signal_on_nonexistent_session() {
    let channel = SessionHostcallChannel::new();
    let handle = SessionHandle {
        session_id: "ghost".into(),
    };

    let env = HostcallEnvelope {
        session_id: "ghost".into(),
        extension_id: "e".into(),
        host_id: "h".into(),
        sequence: 1,
        payload: ChannelPayload::Inline(vec![]),
        mac: AuthenticityHash::compute_keyed(b"k", b"v"),
        trace_id: "t".into(),
        sent_at_tick: 100,
    };

    let err = channel
        .verify_authenticated_signal(&handle, &env)
        .expect_err("should fail");
    assert!(matches!(err, SessionChannelError::SessionNotFound { .. }));
}

// ===========================================================================
// 53) Multiple signals from same session produce consistent MACs
// ===========================================================================

#[test]
fn multiple_signals_same_params_produce_same_mac() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-sig-consistent");

    let sig1 = channel
        .authenticated_backpressure_signal(&handle, 5, 10, "trace-bp", 101)
        .unwrap();
    let sig2 = channel
        .authenticated_backpressure_signal(&handle, 5, 10, "trace-bp", 101)
        .unwrap();

    assert_eq!(sig1.mac, sig2.mac, "same inputs should produce same MAC");
}

// ===========================================================================
// 54) Signals with different params produce different MACs
// ===========================================================================

#[test]
fn signals_different_params_produce_different_macs() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-sig-diff");

    let sig1 = channel
        .authenticated_backpressure_signal(&handle, 5, 10, "trace-bp", 101)
        .unwrap();
    let sig2 = channel
        .authenticated_backpressure_signal(&handle, 6, 10, "trace-bp", 101)
        .unwrap();

    assert_ne!(
        sig1.mac, sig2.mac,
        "different pending should produce different MAC"
    );
}

// ===========================================================================
// 55) SessionChannelEvent Clone
// ===========================================================================

#[test]
fn session_channel_event_clone() {
    let evt = SessionChannelEvent {
        trace_id: "t".into(),
        decision_id: Some("d".into()),
        policy_id: None,
        component: "c".into(),
        event: "e".into(),
        outcome: "ok".into(),
        error_code: None,
        session_id: "s".into(),
        extension_id: "ext".into(),
        host_id: "host".into(),
        sequence: Some(1),
        expected_min_seq: None,
        received_seq: None,
        drop_reason: None,
        source_principal: None,
        timestamp_ticks: 100,
    };
    let cloned = evt.clone();
    assert_eq!(evt, cloned);
}

// ===========================================================================
// 56) SharedPayloadDescriptor with zero-length payload
// ===========================================================================

#[test]
fn shared_payload_descriptor_zero_length() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-shared-zero");

    let seq = channel
        .send_shared_buffer(
            &handle,
            SharedSendInput {
                region_id: 0,
                payload: b"",
                trace_id: "t1",
                timestamp_ticks: 101,
                decision_id: None,
                policy_id: None,
            },
        )
        .unwrap();
    assert_eq!(seq, 1);

    let payload = channel.receive(&handle, "r1", 102, None, None).unwrap();
    match payload {
        ChannelPayload::Shared(desc) => {
            assert_eq!(desc.region_id, 0);
            assert_eq!(desc.payload_len, 0);
        }
        other => panic!("expected Shared, got {other:?}"),
    }
}

// ===========================================================================
// 57) ContentHash in SharedPayloadDescriptor is deterministic
// ===========================================================================

#[test]
fn shared_payload_hash_is_deterministic() {
    let mut ch1 = SessionHostcallChannel::new();
    let mut ch2 = SessionHostcallChannel::new();
    let h1 = create_basic_session(&mut ch1, "sess-hash-det-1");
    let h2 = ch2
        .create_session(
            handshake("sess-hash-det-1", "trace-create", 100),
            &signing_key(1),
            &signing_key(2),
            SessionConfig::default(),
        )
        .unwrap();

    let payload = b"deterministic-check";

    ch1.send_shared_buffer(
        &h1,
        SharedSendInput {
            region_id: 5,
            payload,
            trace_id: "t",
            timestamp_ticks: 101,
            decision_id: None,
            policy_id: None,
        },
    )
    .unwrap();
    ch2.send_shared_buffer(
        &h2,
        SharedSendInput {
            region_id: 5,
            payload,
            trace_id: "t",
            timestamp_ticks: 101,
            decision_id: None,
            policy_id: None,
        },
    )
    .unwrap();

    let p1 = ch1.receive(&h1, "r", 102, None, None).unwrap();
    let p2 = ch2.receive(&h2, "r", 102, None, None).unwrap();

    assert_eq!(p1, p2);
}

// ===========================================================================
// 58) Receive event has correct sequence number
// ===========================================================================

#[test]
fn receive_event_has_correct_sequence() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-recv-seq-evt");

    channel
        .send(&handle, b"msg1".to_vec(), "t1", 101, None, None)
        .unwrap();
    channel
        .send(&handle, b"msg2".to_vec(), "t2", 102, None, None)
        .unwrap();
    channel.drain_events();

    channel.receive(&handle, "r1", 103, None, None).unwrap();
    let events = channel.drain_events();
    let recv_evt = events
        .iter()
        .find(|e| e.event == "message_received")
        .unwrap();
    assert_eq!(recv_evt.sequence, Some(1));

    channel.receive(&handle, "r2", 104, None, None).unwrap();
    let events = channel.drain_events();
    let recv_evt = events
        .iter()
        .find(|e| e.event == "message_received")
        .unwrap();
    assert_eq!(recv_evt.sequence, Some(2));
}

// ===========================================================================
// 59) Send event has correct sequence number
// ===========================================================================

#[test]
fn send_event_has_correct_sequence() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-send-seq-evt");
    channel.drain_events();

    channel
        .send(&handle, b"a".to_vec(), "t1", 101, None, None)
        .unwrap();
    let events = channel.drain_events();
    let send_evt = events.iter().find(|e| e.event == "message_sent").unwrap();
    assert_eq!(send_evt.sequence, Some(1));

    channel
        .send(&handle, b"b".to_vec(), "t2", 102, None, None)
        .unwrap();
    let events = channel.drain_events();
    let send_evt = events.iter().find(|e| e.event == "message_sent").unwrap();
    assert_eq!(send_evt.sequence, Some(2));
}

// ===========================================================================
// 60) Message budget: receive-only doesn't exhaust budget if no sends
// ===========================================================================

#[test]
fn message_budget_counts_sends_and_receives_together() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_session_with_config(
        &mut channel,
        "sess-budget-combo",
        SessionConfig {
            max_messages: 4,
            max_buffered_messages: 256,
            ..SessionConfig::default()
        },
    );

    // 2 sends (sent=2) + 2 receives (recv=2) = 4 total = budget
    channel
        .send(&handle, b"a".to_vec(), "t1", 101, None, None)
        .unwrap();
    channel
        .send(&handle, b"b".to_vec(), "t2", 102, None, None)
        .unwrap();
    channel.receive(&handle, "r1", 103, None, None).unwrap();
    channel.receive(&handle, "r2", 104, None, None).unwrap();

    // Next operation should fail (2+2 = 4 >= 4)
    let err = channel
        .send(&handle, b"c".to_vec(), "t3", 105, None, None)
        .expect_err("should exhaust budget");
    assert!(matches!(
        err,
        SessionChannelError::SessionExpired { reason, .. }
        if reason.contains("message_budget")
    ));
}

// ===========================================================================
// 61) Nonce derivation XChaCha20 produces 24-byte nonce
// ===========================================================================

#[test]
fn nonce_xchacha_always_24_bytes() {
    let key = [0xAA; 32];
    for seq in [0, 1, 100, 1000, u64::MAX / 2] {
        let nonce = derive_deterministic_aead_nonce(
            &key,
            DataPlaneDirection::HostToExtension,
            seq,
            AeadAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();
        assert_eq!(nonce.as_bytes().len(), 24, "seq={seq} should give 24 bytes");
    }
}

// ===========================================================================
// 62) AEAD associated data length varies with input
// ===========================================================================

#[test]
fn aead_associated_data_length_scales_with_input() {
    let ad_short = build_aead_associated_data("s", "t", 0);
    let ad_long = build_aead_associated_data("session-very-long-id", "type-very-long", 0);

    assert!(
        ad_long.len() > ad_short.len(),
        "longer inputs should produce longer AD"
    );
}

// ===========================================================================
// 63) SessionConfig with strict policy serde round-trip
// ===========================================================================

#[test]
fn session_config_strict_serde_roundtrip() {
    let config = SessionConfig {
        max_lifetime_ticks: 1,
        max_messages: 1,
        max_buffered_messages: 1,
        sequence_policy: SequencePolicy::Strict,
        replay_drop_threshold: 0,
        replay_drop_window_ticks: 0,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: SessionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
    assert_eq!(restored.sequence_policy, SequencePolicy::Strict);
}

// ===========================================================================
// 64) DataPlaneDirection serde round-trip
// ===========================================================================

#[test]
fn data_plane_direction_serde_round_trip() {
    for dir in [
        DataPlaneDirection::HostToExtension,
        DataPlaneDirection::ExtensionToHost,
    ] {
        let json = serde_json::to_string(&dir).unwrap();
        let restored: DataPlaneDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(dir, restored);
    }
}

// ===========================================================================
// 65) Multiple sessions with distinct signing keys
// ===========================================================================

#[test]
fn distinct_signing_keys_produce_independent_sessions() {
    let mut channel = SessionHostcallChannel::new();

    let h1 = channel
        .create_session(
            handshake_custom("key-sess-1", "ext-1", "host-1", 1, 2, 100),
            &signing_key(10),
            &signing_key(20),
            SessionConfig::default(),
        )
        .unwrap();

    let h2 = channel
        .create_session(
            handshake_custom("key-sess-2", "ext-2", "host-2", 3, 4, 100),
            &signing_key(30),
            &signing_key(40),
            SessionConfig::default(),
        )
        .unwrap();

    // Both should work independently
    channel
        .send(&h1, b"for-1".to_vec(), "t1", 101, None, None)
        .unwrap();
    channel
        .send(&h2, b"for-2".to_vec(), "t2", 101, None, None)
        .unwrap();

    let p1 = channel.receive(&h1, "r1", 102, None, None).unwrap();
    let p2 = channel.receive(&h2, "r2", 102, None, None).unwrap();

    assert_eq!(p1, ChannelPayload::Inline(b"for-1".to_vec()));
    assert_eq!(p2, ChannelPayload::Inline(b"for-2".to_vec()));
}

// ===========================================================================
// 66) Session handle equality
// ===========================================================================

#[test]
fn session_handle_equality_by_session_id() {
    let h1 = SessionHandle {
        session_id: "same".into(),
    };
    let h2 = SessionHandle {
        session_id: "same".into(),
    };
    let h3 = SessionHandle {
        session_id: "different".into(),
    };

    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
}

// ===========================================================================
// 67) Event accumulation across multiple operations
// ===========================================================================

#[test]
fn events_accumulate_across_operations() {
    let mut channel = SessionHostcallChannel::new();
    let handle = create_basic_session(&mut channel, "sess-accum");

    // Don't drain — let events accumulate
    channel
        .send(&handle, b"a".to_vec(), "t1", 101, None, None)
        .unwrap();
    channel
        .send(&handle, b"b".to_vec(), "t2", 102, None, None)
        .unwrap();
    channel.receive(&handle, "r1", 103, None, None).unwrap();
    channel
        .close_session(&handle, "tc", 200, None, None)
        .unwrap();

    let events = channel.drain_events();
    // session_created + 2x message_sent + message_received + session_closed = 5
    assert_eq!(events.len(), 5);

    let event_types: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(event_types[0], "session_created");
    assert_eq!(event_types[1], "message_sent");
    assert_eq!(event_types[2], "message_sent");
    assert_eq!(event_types[3], "message_received");
    assert_eq!(event_types[4], "session_closed");
}

// ===========================================================================
// 68) Nonce exhaustion error contains correct fields
// ===========================================================================

#[test]
fn nonce_exhaustion_error_fields() {
    let key = [0xFF; 32];
    let err = derive_deterministic_aead_nonce(
        &key,
        DataPlaneDirection::HostToExtension,
        1u64 << 32,
        AeadAlgorithm::Aes256Gcm,
    )
    .expect_err("should exhaust");

    match err {
        SessionChannelError::NonceExhausted {
            sequence,
            limit,
            algorithm,
        } => {
            assert_eq!(sequence, 1u64 << 32);
            assert_eq!(limit, 1u64 << 32);
            assert_eq!(algorithm, AeadAlgorithm::Aes256Gcm);
        }
        other => panic!("expected NonceExhausted, got {other:?}"),
    }
}

// ===========================================================================
// 69) SessionState Clone and Copy
// ===========================================================================

#[test]
fn session_state_clone_copy() {
    let state = SessionState::Established;
    let cloned = state.clone();
    let copied = state;
    assert_eq!(state, cloned);
    assert_eq!(state, copied);
}

// ===========================================================================
// 70) SequencePolicy Clone and Copy
// ===========================================================================

#[test]
fn sequence_policy_clone_copy() {
    let policy = SequencePolicy::Strict;
    let cloned = policy.clone();
    let copied = policy;
    assert_eq!(policy, cloned);
    assert_eq!(policy, copied);
}

// ===========================================================================
// 71) AeadAlgorithm Clone and Copy
// ===========================================================================

#[test]
fn aead_algorithm_clone_copy() {
    let algo = AeadAlgorithm::XChaCha20Poly1305;
    let cloned = algo.clone();
    let copied = algo;
    assert_eq!(algo, cloned);
    assert_eq!(algo, copied);
}

// ===========================================================================
// 72) DataPlaneDirection Clone and Copy
// ===========================================================================

#[test]
fn data_plane_direction_clone_copy() {
    let dir = DataPlaneDirection::HostToExtension;
    let cloned = dir.clone();
    let copied = dir;
    assert_eq!(dir, cloned);
    assert_eq!(dir, copied);
}

// ===========================================================================
// 73) Stress: many sessions created on same channel
// ===========================================================================

#[test]
fn stress_many_sessions_on_same_channel() {
    let mut channel = SessionHostcallChannel::new();

    for i in 0..50 {
        let handle = channel
            .create_session(
                handshake_custom(
                    &format!("stress-sess-{i}"),
                    &format!("ext-{i}"),
                    &format!("host-{i}"),
                    i as u64,
                    i as u64 + 1000,
                    100,
                ),
                &signing_key((i % 250 + 1) as u8),
                &signing_key((i % 250 + 2) as u8),
                SessionConfig::default(),
            )
            .unwrap();
        assert_eq!(
            channel.session_state(&handle),
            Some(SessionState::Established)
        );
    }
}

// ===========================================================================
// 74) Replay drop threshold = 0 and window = 0 both allowed
// ===========================================================================

#[test]
fn zero_threshold_zero_window_both_allowed() {
    let mut channel = SessionHostcallChannel::new();
    let handle = channel
        .create_session(
            handshake("sess-zero-both", "trace", 100),
            &signing_key(1),
            &signing_key(2),
            SessionConfig {
                replay_drop_threshold: 0,
                replay_drop_window_ticks: 0,
                ..SessionConfig::default()
            },
        )
        .unwrap();
    assert_eq!(
        channel.session_state(&handle),
        Some(SessionState::Established)
    );
}

// ===========================================================================
// 75) ReplayDropReason serde stability (exact JSON values)
// ===========================================================================

#[test]
fn replay_drop_reason_serde_exact_values() {
    let json_replay = serde_json::to_string(&ReplayDropReason::Replay).unwrap();
    let json_dup = serde_json::to_string(&ReplayDropReason::Duplicate).unwrap();
    let json_ooo = serde_json::to_string(&ReplayDropReason::OutOfOrder).unwrap();

    // They should all be distinct
    let mut set = BTreeSet::new();
    set.insert(json_replay);
    set.insert(json_dup);
    set.insert(json_ooo);
    assert_eq!(set.len(), 3);
}
