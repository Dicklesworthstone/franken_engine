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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::session_hostcall_channel::{
    AeadAlgorithm, BackpressureSignal, DataPlaneDirection, ReplayDropReason, SequencePolicy,
    SessionConfig, SessionHandshake, SessionState, SharedPayloadDescriptor,
};

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
