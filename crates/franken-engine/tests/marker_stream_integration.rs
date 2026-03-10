//! Integration tests for the `marker_stream` module.
//!
//! Covers areas not exercised by inline unit tests: CorrelationId validation
//! edge cases, by_event_type queries, verify_range edge cases, checkpoint key
//! sensitivity, verify_head failure paths, serde roundtrips for compound types,
//! mixed decision type chains, stress tests, and multi-query cross-checks.

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

use frankenengine_engine::marker_stream::{
    AuditChainHead, ChainIntegrityError, CorrelationId, DecisionMarker, DecisionMarkerStream,
    DecisionType, IntegrityCheckpoint, MarkerEvent, MarkerInput, PolicyTransitionKind,
    RedactedPayload, RevocationKind, SecurityActionKind, TraceContext,
};

use frankenengine_engine::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn evidence_hash() -> ContentHash {
    ContentHash::compute(b"integration-evidence")
}

fn make_stream() -> DecisionMarkerStream {
    DecisionMarkerStream::new(5, b"integration-checkpoint-key".to_vec())
}

fn quarantine_input(suffix: &str) -> MarkerInput {
    MarkerInput {
        timestamp_ticks: 100,
        epoch_id: 1,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: format!("dec-{suffix}"),
        policy_id: Some("policy-default".into()),
        correlation_id: CorrelationId::new(format!("corr-{suffix}")).unwrap(),
        trace_context: None,
        principal_id: Some("principal-op".into()),
        zone_id: Some("zone-a".into()),
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "operator".into(),
        payload_summary: format!("quarantine target-{suffix}"),
        full_payload: None,
        trace_id: format!("trace-{suffix}"),
    }
}

fn make_input(decision_type: DecisionType, suffix: &str, ticks: u64, epoch: u64) -> MarkerInput {
    MarkerInput {
        timestamp_ticks: ticks,
        epoch_id: epoch,
        decision_type,
        decision_id: format!("dec-{suffix}"),
        policy_id: Some(format!("policy-{suffix}")),
        correlation_id: CorrelationId::new(format!("corr-{suffix}")).unwrap(),
        trace_context: None,
        principal_id: Some(format!("principal-{suffix}")),
        zone_id: Some(format!("zone-{suffix}")),
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "system".into(),
        payload_summary: format!("summary-{suffix}"),
        full_payload: None,
        trace_id: format!("trace-{suffix}"),
    }
}

// ---------------------------------------------------------------------------
// CorrelationId validation
// ---------------------------------------------------------------------------

#[test]
fn correlation_id_rejects_empty_string() {
    assert!(CorrelationId::new("").is_err());
}

#[test]
fn correlation_id_rejects_too_long() {
    let long = "a".repeat(129);
    assert!(CorrelationId::new(long).is_err());
}

#[test]
fn correlation_id_accepts_max_length() {
    let max = "a".repeat(128);
    assert!(CorrelationId::new(max).is_ok());
}

#[test]
fn correlation_id_rejects_invalid_characters() {
    assert!(CorrelationId::new("has space").is_err());
    assert!(CorrelationId::new("has@symbol").is_err());
    assert!(CorrelationId::new("has/slash").is_err());
    assert!(CorrelationId::new("has:colon").is_err());
}

#[test]
fn correlation_id_accepts_valid_characters() {
    assert!(CorrelationId::new("valid-id_123.test").is_ok());
    assert!(CorrelationId::new("UPPERCASE").is_ok());
    assert!(CorrelationId::new("a").is_ok());
}

#[test]
fn correlation_id_display_matches_inner_value() {
    let id = CorrelationId::new("my-corr-id").unwrap();
    assert_eq!(id.to_string(), "my-corr-id");
    assert_eq!(id.as_str(), "my-corr-id");
}

#[test]
fn correlation_id_serde_roundtrip() {
    let id = CorrelationId::new("serde-roundtrip-test").unwrap();
    let json = serde_json::to_string(&id).unwrap();
    let restored: CorrelationId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

// ---------------------------------------------------------------------------
// DecisionType Display and serde
// ---------------------------------------------------------------------------

#[test]
fn decision_type_display_all_variants() {
    let cases: Vec<(DecisionType, &str)> = vec![
        (
            DecisionType::SecurityAction {
                action: SecurityActionKind::Quarantine,
            },
            "security_action:quarantine",
        ),
        (
            DecisionType::SecurityAction {
                action: SecurityActionKind::Suspend,
            },
            "security_action:suspend",
        ),
        (
            DecisionType::SecurityAction {
                action: SecurityActionKind::Terminate,
            },
            "security_action:terminate",
        ),
        (
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Activation,
            },
            "policy_transition:activation",
        ),
        (
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::Deactivation,
            },
            "policy_transition:deactivation",
        ),
        (
            DecisionType::PolicyTransition {
                transition: PolicyTransitionKind::EpochAdvancement,
            },
            "policy_transition:epoch_advancement",
        ),
        (
            DecisionType::RevocationEvent {
                revocation: RevocationKind::Issuance,
            },
            "revocation_event:issuance",
        ),
        (
            DecisionType::RevocationEvent {
                revocation: RevocationKind::PropagationConfirmation,
            },
            "revocation_event:propagation_confirmation",
        ),
        (
            DecisionType::EpochTransition {
                from_epoch: 3,
                to_epoch: 4,
            },
            "epoch_transition:3->4",
        ),
        (
            DecisionType::EmergencyOverride {
                override_reason: "critical".into(),
            },
            "emergency_override",
        ),
        (
            DecisionType::GuardrailTriggered {
                guardrail_id: "GR-001".into(),
            },
            "guardrail_triggered:GR-001",
        ),
    ];

    for (dt, expected) in &cases {
        assert_eq!(dt.to_string(), *expected, "mismatch for {dt:?}");
    }
}

#[test]
fn decision_type_serde_roundtrip_all_variants() {
    let variants = vec![
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
            from_epoch: 10,
            to_epoch: 11,
        },
        DecisionType::EmergencyOverride {
            override_reason: "reason".into(),
        },
        DecisionType::GuardrailTriggered {
            guardrail_id: "gr-1".into(),
        },
    ];

    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: DecisionType = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored, "serde roundtrip failed for {variant:?}");
    }
}

// ---------------------------------------------------------------------------
// TraceContext / RedactedPayload serde
// ---------------------------------------------------------------------------

#[test]
fn trace_context_serde_roundtrip() {
    let ctx = TraceContext {
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into(),
        tracestate: Some("vendor=value".into()),
        baggage: Some("tenant=alpha".into()),
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: TraceContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

#[test]
fn trace_context_serde_with_none_fields() {
    let ctx = TraceContext {
        traceparent: "00-trace-id-span-id-00".into(),
        tracestate: None,
        baggage: None,
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: TraceContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

#[test]
fn redacted_payload_serde_roundtrip() {
    let rp = RedactedPayload {
        redacted_summary: "[redacted]".into(),
        payload_hash: ContentHash::compute(b"secret-content"),
        redaction_applied: true,
    };
    let json = serde_json::to_string(&rp).unwrap();
    let restored: RedactedPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(rp, restored);
}

// ---------------------------------------------------------------------------
// by_event_type queries
// ---------------------------------------------------------------------------

#[test]
fn by_event_type_returns_matching_decision_types() {
    let mut stream = make_stream();

    stream.append(make_input(
        DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        "sec-1",
        100,
        1,
    ));
    stream.append(make_input(
        DecisionType::PolicyTransition {
            transition: PolicyTransitionKind::Activation,
        },
        "pol-1",
        101,
        1,
    ));
    stream.append(make_input(
        DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        "sec-2",
        102,
        1,
    ));
    stream.append(make_input(
        DecisionType::RevocationEvent {
            revocation: RevocationKind::Issuance,
        },
        "rev-1",
        103,
        1,
    ));

    assert_eq!(stream.by_event_type("security_action:quarantine").len(), 2);
    assert_eq!(
        stream.by_event_type("policy_transition:activation").len(),
        1
    );
    assert_eq!(stream.by_event_type("revocation_event:issuance").len(), 1);
    assert!(stream.by_event_type("nonexistent").is_empty());
}

#[test]
fn by_event_type_distinguishes_sub_variants() {
    let mut stream = make_stream();

    stream.append(make_input(
        DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        "q1",
        100,
        1,
    ));
    stream.append(make_input(
        DecisionType::SecurityAction {
            action: SecurityActionKind::Suspend,
        },
        "s1",
        101,
        1,
    ));
    stream.append(make_input(
        DecisionType::SecurityAction {
            action: SecurityActionKind::Terminate,
        },
        "t1",
        102,
        1,
    ));

    assert_eq!(stream.by_event_type("security_action:quarantine").len(), 1);
    assert_eq!(stream.by_event_type("security_action:suspend").len(), 1);
    assert_eq!(stream.by_event_type("security_action:terminate").len(), 1);
}

// ---------------------------------------------------------------------------
// Mixed decision types in a single chain
// ---------------------------------------------------------------------------

#[test]
fn mixed_decision_types_maintain_chain_integrity() {
    let mut stream = make_stream();

    let types = vec![
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
            override_reason: "critical-situation".into(),
        },
        DecisionType::GuardrailTriggered {
            guardrail_id: "GR-001".into(),
        },
        DecisionType::SecurityAction {
            action: SecurityActionKind::Suspend,
        },
        DecisionType::PolicyTransition {
            transition: PolicyTransitionKind::Deactivation,
        },
        DecisionType::RevocationEvent {
            revocation: RevocationKind::PropagationConfirmation,
        },
        DecisionType::SecurityAction {
            action: SecurityActionKind::Terminate,
        },
        DecisionType::PolicyTransition {
            transition: PolicyTransitionKind::EpochAdvancement,
        },
    ];

    for (i, dt) in types.into_iter().enumerate() {
        stream.append(make_input(dt, &format!("mixed-{i}"), 100 + i as u64, 1));
    }

    assert_eq!(stream.len(), 11);
    assert!(stream.verify_chain().is_ok());
    assert!(stream.verify_head().is_ok());

    // Verify the chain links are continuous.
    let markers = stream.markers();
    for i in 1..markers.len() {
        assert_eq!(markers[i].prev_marker_hash, markers[i - 1].marker_hash);
    }
}

// ---------------------------------------------------------------------------
// verify_range edge cases
// ---------------------------------------------------------------------------

#[test]
fn verify_range_single_marker() {
    let mut stream = make_stream();
    for i in 0..5 {
        stream.append(quarantine_input(&i.to_string()));
    }
    // Range containing exactly one marker.
    assert!(stream.verify_range(3, 3).is_ok());
}

#[test]
fn verify_range_full_stream() {
    let mut stream = make_stream();
    for i in 0..10 {
        stream.append(quarantine_input(&i.to_string()));
    }
    assert!(stream.verify_range(1, 10).is_ok());
}

#[test]
fn verify_range_nonexistent_ids_returns_error() {
    let mut stream = make_stream();
    for i in 0..5 {
        stream.append(quarantine_input(&i.to_string()));
    }
    // IDs that don't exist.
    assert!(stream.verify_range(99, 100).is_err());
}

// Note: tamper detection tests for verify_range are in inline unit tests
// which have access to private fields for mutation.

// ---------------------------------------------------------------------------
// Checkpoint key sensitivity
// ---------------------------------------------------------------------------

#[test]
fn different_checkpoint_keys_produce_different_signed_hashes() {
    let mut stream_a = DecisionMarkerStream::new(2, b"key-alpha".to_vec());
    let mut stream_b = DecisionMarkerStream::new(2, b"key-beta".to_vec());

    for i in 0..4 {
        stream_a.append(quarantine_input(&format!("k-{i}")));
        stream_b.append(quarantine_input(&format!("k-{i}")));
    }

    assert!(!stream_a.checkpoints().is_empty());
    assert!(!stream_b.checkpoints().is_empty());

    // Signed hashes should differ because keys differ.
    assert_ne!(
        stream_a.checkpoints()[0].signed_hash,
        stream_b.checkpoints()[0].signed_hash
    );

    // But marker hashes themselves should match (same data).
    assert_eq!(
        stream_a.checkpoints()[0].marker_hash,
        stream_b.checkpoints()[0].marker_hash
    );
}

#[test]
fn checkpoint_interval_one_emits_checkpoint_every_marker() {
    let mut stream = DecisionMarkerStream::new(1, b"key".to_vec());
    for i in 0..7 {
        stream.append(quarantine_input(&i.to_string()));
    }
    assert_eq!(stream.checkpoints().len(), 7);
    for (i, cp) in stream.checkpoints().iter().enumerate() {
        assert_eq!(cp.at_marker_id, (i + 1) as u64);
        assert_eq!(cp.chain_length, (i + 1) as u64);
    }
}

#[test]
fn checkpoint_interval_zero_emits_no_checkpoints() {
    let mut stream = DecisionMarkerStream::new(0, b"key".to_vec());
    for i in 0..10 {
        stream.append(quarantine_input(&i.to_string()));
    }
    assert!(stream.checkpoints().is_empty());
}

// ---------------------------------------------------------------------------
// verify_head failure paths
// ---------------------------------------------------------------------------

#[test]
fn verify_head_on_empty_stream_succeeds() {
    let stream = make_stream();
    assert!(stream.verify_head().is_ok());
}

// Note: verify_head tamper detection tests require mutating private fields
// and are covered by inline unit tests.

// ---------------------------------------------------------------------------
// Chain head advances correctly
// ---------------------------------------------------------------------------

#[test]
fn chain_head_tracks_latest_marker() {
    let mut stream = make_stream();

    assert!(stream.chain_head().is_none());

    stream.append(quarantine_input("1"));
    let head1 = stream.chain_head().unwrap().clone();
    assert_eq!(head1.head_marker_id, 1);

    stream.append(quarantine_input("2"));
    let head2 = stream.chain_head().unwrap().clone();
    assert_eq!(head2.head_marker_id, 2);
    assert_ne!(head1.rolling_chain_hash, head2.rolling_chain_hash);
    assert_ne!(head1.signed_head_hash, head2.signed_head_hash);
}

#[test]
fn chain_head_signed_hash_depends_on_checkpoint_key() {
    let mut stream_a = DecisionMarkerStream::new(5, b"key-a".to_vec());
    let mut stream_b = DecisionMarkerStream::new(5, b"key-b".to_vec());

    stream_a.append(quarantine_input("same"));
    stream_b.append(quarantine_input("same"));

    let head_a = stream_a.chain_head().unwrap();
    let head_b = stream_b.chain_head().unwrap();

    // Rolling hashes are the same (same data), but signed hashes differ.
    assert_eq!(head_a.rolling_chain_hash, head_b.rolling_chain_hash);
    assert_ne!(head_a.signed_head_hash, head_b.signed_head_hash);
}

// ---------------------------------------------------------------------------
// Marker with all optional fields populated vs none
// ---------------------------------------------------------------------------

#[test]
fn marker_with_all_optional_fields() {
    let mut stream = make_stream();
    stream.append(MarkerInput {
        timestamp_ticks: 500,
        epoch_id: 42,
        decision_type: DecisionType::EmergencyOverride {
            override_reason: "operator override".into(),
        },
        decision_id: "dec-full".into(),
        policy_id: Some("policy-full".into()),
        correlation_id: CorrelationId::new("corr-full").unwrap(),
        trace_context: Some(TraceContext {
            traceparent: "00-abcdef-123456-01".into(),
            tracestate: Some("vendor=val".into()),
            baggage: Some("key=value".into()),
        }),
        principal_id: Some("principal-full".into()),
        zone_id: Some("zone-full".into()),
        error_code: Some("ERR-42".into()),
        evidence_entry_hash: evidence_hash(),
        actor: "human-operator".into(),
        payload_summary: "full-summary".into(),
        full_payload: Some("full-sensitive-payload".into()),
        trace_id: "trace-full".into(),
    });

    let marker = stream.get(1).unwrap();
    assert_eq!(marker.epoch_id, 42);
    assert!(marker.trace_context.is_some());
    assert_eq!(marker.principal_id.as_deref(), Some("principal-full"));
    assert_eq!(marker.zone_id.as_deref(), Some("zone-full"));
    assert_eq!(marker.error_code.as_deref(), Some("ERR-42"));
    assert!(marker.redacted_payload.redaction_applied);
    // full_payload is hashed, not stored directly.
    assert_eq!(
        marker.redacted_payload.payload_hash,
        ContentHash::compute(b"full-sensitive-payload")
    );
    assert!(stream.verify_chain().is_ok());
}

#[test]
fn marker_with_no_optional_fields() {
    let mut stream = make_stream();
    stream.append(MarkerInput {
        timestamp_ticks: 1,
        epoch_id: 0,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: "dec-minimal".into(),
        policy_id: None,
        correlation_id: CorrelationId::new("corr-minimal").unwrap(),
        trace_context: None,
        principal_id: None,
        zone_id: None,
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "sys".into(),
        payload_summary: "minimal".into(),
        full_payload: None,
        trace_id: "trace-minimal".into(),
    });

    let marker = stream.get(1).unwrap();
    assert!(marker.policy_id.is_none());
    assert!(marker.trace_context.is_none());
    assert!(marker.principal_id.is_none());
    assert!(marker.zone_id.is_none());
    assert!(marker.error_code.is_none());
    assert!(stream.verify_chain().is_ok());
}

#[test]
fn optional_fields_affect_hash() {
    let mut stream_with = make_stream();
    let mut stream_without = make_stream();

    stream_with.append(MarkerInput {
        timestamp_ticks: 100,
        epoch_id: 1,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: "dec-same".into(),
        policy_id: Some("policy".into()),
        correlation_id: CorrelationId::new("corr-same").unwrap(),
        trace_context: Some(TraceContext {
            traceparent: "tp".into(),
            tracestate: None,
            baggage: None,
        }),
        principal_id: Some("principal".into()),
        zone_id: Some("zone".into()),
        error_code: Some("ERR-1".into()),
        evidence_entry_hash: evidence_hash(),
        actor: "operator".into(),
        payload_summary: "same-summary".into(),
        full_payload: None,
        trace_id: "trace-same".into(),
    });

    stream_without.append(MarkerInput {
        timestamp_ticks: 100,
        epoch_id: 1,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: "dec-same".into(),
        policy_id: None,
        correlation_id: CorrelationId::new("corr-same").unwrap(),
        trace_context: None,
        principal_id: None,
        zone_id: None,
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "operator".into(),
        payload_summary: "same-summary".into(),
        full_payload: None,
        trace_id: "trace-same".into(),
    });

    assert_ne!(
        stream_with.markers()[0].marker_hash,
        stream_without.markers()[0].marker_hash,
    );
}

// ---------------------------------------------------------------------------
// Events (drain_events)
// ---------------------------------------------------------------------------

#[test]
fn events_emitted_for_each_append() {
    let mut stream = make_stream();
    for i in 0..3 {
        stream.append(quarantine_input(&i.to_string()));
    }

    let events = stream.drain_events();
    assert_eq!(events.len(), 3);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.marker_id, (i + 1) as u64);
        assert_eq!(event.chain_length, (i + 1) as u64);
        assert_eq!(event.component, "marker_stream");
        assert_eq!(event.event, "marker_appended");
        assert_eq!(event.outcome, "ok");
    }
}

#[test]
fn drain_events_clears_buffer() {
    let mut stream = make_stream();
    stream.append(quarantine_input("1"));
    assert_eq!(stream.drain_events().len(), 1);
    // Second drain should be empty.
    assert!(stream.drain_events().is_empty());
}

#[test]
fn events_capture_decision_metadata() {
    let mut stream = make_stream();
    stream.append(MarkerInput {
        timestamp_ticks: 200,
        epoch_id: 5,
        decision_type: DecisionType::GuardrailTriggered {
            guardrail_id: "GR-TEST".into(),
        },
        decision_id: "dec-gr".into(),
        policy_id: Some("policy-gr".into()),
        correlation_id: CorrelationId::new("corr-gr").unwrap(),
        trace_context: None,
        principal_id: Some("principal-gr".into()),
        zone_id: None,
        error_code: Some("ERR-GR".into()),
        evidence_entry_hash: evidence_hash(),
        actor: "runtime".into(),
        payload_summary: "guardrail triggered".into(),
        full_payload: None,
        trace_id: "trace-gr".into(),
    });

    let events = stream.drain_events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.marker_type, "guardrail_triggered:GR-TEST");
    assert_eq!(event.decision_id, "dec-gr");
    assert_eq!(event.policy_id.as_deref(), Some("policy-gr"));
    assert_eq!(event.principal_id.as_deref(), Some("principal-gr"));
    assert_eq!(event.correlation_id, "corr-gr");
    assert_eq!(event.trace_id, "trace-gr");
    assert_eq!(event.error_code.as_deref(), Some("ERR-GR"));
}

// ---------------------------------------------------------------------------
// Serde roundtrips for compound types
// ---------------------------------------------------------------------------

#[test]
fn decision_marker_full_serde_roundtrip() {
    let mut stream = make_stream();
    stream.append(MarkerInput {
        timestamp_ticks: 999,
        epoch_id: 77,
        decision_type: DecisionType::EpochTransition {
            from_epoch: 76,
            to_epoch: 77,
        },
        decision_id: "dec-epoch".into(),
        policy_id: Some("policy-epoch".into()),
        correlation_id: CorrelationId::new("corr-epoch").unwrap(),
        trace_context: Some(TraceContext {
            traceparent: "00-trace-id-span-01".into(),
            tracestate: Some("vendor=val".into()),
            baggage: Some("bag=val".into()),
        }),
        principal_id: Some("principal-epoch".into()),
        zone_id: Some("zone-epoch".into()),
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "orchestrator".into(),
        payload_summary: "epoch advancement".into(),
        full_payload: Some("full-epoch-data".into()),
        trace_id: "trace-epoch".into(),
    });

    let marker = stream.markers()[0].clone();
    let json = serde_json::to_string(&marker).unwrap();
    let restored: DecisionMarker = serde_json::from_str(&json).unwrap();
    assert_eq!(marker, restored);
}

#[test]
fn audit_chain_head_serde_roundtrip() {
    let mut stream = make_stream();
    stream.append(quarantine_input("head-serde"));

    let head = stream.chain_head().unwrap().clone();
    let json = serde_json::to_string(&head).unwrap();
    let restored: AuditChainHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, restored);
}

#[test]
fn integrity_checkpoint_serde_roundtrip() {
    let mut stream = DecisionMarkerStream::new(1, b"serde-key".to_vec());
    stream.append(quarantine_input("cp-serde"));

    let cp = stream.checkpoints()[0].clone();
    let json = serde_json::to_string(&cp).unwrap();
    let restored: IntegrityCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(cp, restored);
}

#[test]
fn chain_integrity_error_serde_all_variants() {
    let errors = vec![
        ChainIntegrityError::EmptyStream,
        ChainIntegrityError::MarkerHashMismatch {
            marker_id: 7,
            expected: ContentHash([0xaa; 32]),
            computed: ContentHash([0xbb; 32]),
        },
        ChainIntegrityError::ChainLinkBroken {
            marker_id: 3,
            expected_prev: ContentHash([0x11; 32]),
            actual_prev: ContentHash([0x22; 32]),
        },
        ChainIntegrityError::NonMonotonicId {
            marker_id: 2,
            prev_marker_id: 5,
        },
        ChainIntegrityError::HeadMismatch,
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ChainIntegrityError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "serde roundtrip failed for {err:?}");
    }
}

#[test]
fn marker_event_serde_roundtrip() {
    let event = MarkerEvent {
        marker_id: 42,
        marker_type: "security_action:quarantine".into(),
        chain_length: 42,
        decision_id: "dec-42".into(),
        policy_id: Some("policy-42".into()),
        principal_id: Some("principal-42".into()),
        correlation_id: "corr-42".into(),
        trace_id: "trace-42".into(),
        component: "marker_stream".into(),
        event: "marker_appended".into(),
        outcome: "ok".into(),
        error_code: Some("ERR-42".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: MarkerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// Payload redaction
// ---------------------------------------------------------------------------

#[test]
fn full_payload_hashed_not_stored() {
    let mut stream = make_stream();
    let secret = "super-secret-api-key-12345";
    stream.append(MarkerInput {
        timestamp_ticks: 100,
        epoch_id: 1,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: "dec-redact".into(),
        policy_id: None,
        correlation_id: CorrelationId::new("corr-redact").unwrap(),
        trace_context: None,
        principal_id: None,
        zone_id: None,
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "sys".into(),
        payload_summary: "[REDACTED]".into(),
        full_payload: Some(secret.into()),
        trace_id: "trace-redact".into(),
    });

    let marker = stream.get(1).unwrap();
    // Summary should not contain the secret.
    assert!(!marker.redacted_payload.redacted_summary.contains(secret));
    // But the hash should reflect the full payload.
    assert_eq!(
        marker.redacted_payload.payload_hash,
        ContentHash::compute(secret.as_bytes())
    );
    assert!(marker.redacted_payload.redaction_applied);
}

#[test]
fn no_full_payload_uses_summary_for_hash() {
    let mut stream = make_stream();
    stream.append(MarkerInput {
        timestamp_ticks: 100,
        epoch_id: 1,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: "dec-no-full".into(),
        policy_id: None,
        correlation_id: CorrelationId::new("corr-no-full").unwrap(),
        trace_context: None,
        principal_id: None,
        zone_id: None,
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "sys".into(),
        payload_summary: "quarantine target-x".into(),
        full_payload: None,
        trace_id: "trace-no-full".into(),
    });

    let marker = stream.get(1).unwrap();
    assert_eq!(
        marker.redacted_payload.payload_hash,
        ContentHash::compute(b"quarantine target-x")
    );
}

// ---------------------------------------------------------------------------
// Multi-query cross-checks
// ---------------------------------------------------------------------------

#[test]
fn queries_cross_check_against_full_markers() {
    let mut stream = make_stream();

    // Mix of decision types, principals, error codes, correlation IDs.
    stream.append(MarkerInput {
        timestamp_ticks: 100,
        epoch_id: 1,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: "dec-cross-1".into(),
        policy_id: Some("policy-a".into()),
        correlation_id: CorrelationId::new("corr-flow-x").unwrap(),
        trace_context: None,
        principal_id: Some("alice".into()),
        zone_id: None,
        error_code: Some("ERR-1".into()),
        evidence_entry_hash: evidence_hash(),
        actor: "sys".into(),
        payload_summary: "q1".into(),
        full_payload: None,
        trace_id: "trace-cross-1".into(),
    });
    stream.append(MarkerInput {
        timestamp_ticks: 200,
        epoch_id: 2,
        decision_type: DecisionType::PolicyTransition {
            transition: PolicyTransitionKind::Activation,
        },
        decision_id: "dec-cross-2".into(),
        policy_id: Some("policy-b".into()),
        correlation_id: CorrelationId::new("corr-flow-x").unwrap(),
        trace_context: None,
        principal_id: Some("bob".into()),
        zone_id: None,
        error_code: None,
        evidence_entry_hash: evidence_hash(),
        actor: "sys".into(),
        payload_summary: "p1".into(),
        full_payload: None,
        trace_id: "trace-cross-2".into(),
    });
    stream.append(MarkerInput {
        timestamp_ticks: 300,
        epoch_id: 3,
        decision_type: DecisionType::SecurityAction {
            action: SecurityActionKind::Quarantine,
        },
        decision_id: "dec-cross-3".into(),
        policy_id: Some("policy-a".into()),
        correlation_id: CorrelationId::new("corr-flow-y").unwrap(),
        trace_context: None,
        principal_id: Some("alice".into()),
        zone_id: None,
        error_code: Some("ERR-1".into()),
        evidence_entry_hash: evidence_hash(),
        actor: "sys".into(),
        payload_summary: "q2".into(),
        full_payload: None,
        trace_id: "trace-cross-3".into(),
    });

    // by_correlation_id
    assert_eq!(stream.by_correlation_id("corr-flow-x").len(), 2);
    assert_eq!(stream.by_correlation_id("corr-flow-y").len(), 1);

    // by_event_type
    assert_eq!(stream.by_event_type("security_action:quarantine").len(), 2);
    assert_eq!(
        stream.by_event_type("policy_transition:activation").len(),
        1
    );

    // by_principal_id
    assert_eq!(stream.by_principal_id("alice").len(), 2);
    assert_eq!(stream.by_principal_id("bob").len(), 1);

    // by_error_code
    assert_eq!(stream.by_error_code("ERR-1").len(), 2);

    // by_time_range
    assert_eq!(stream.by_time_range(100, 200).len(), 2);
    assert_eq!(stream.by_time_range(300, 300).len(), 1);
    assert_eq!(stream.by_time_range(150, 250).len(), 1);
}

// Note: field-level tamper detection tests (epoch_id, decision_id, actor,
// evidence_hash, timestamp) require mutating private `markers` field and
// are covered by inline unit tests.

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn chain_integrity_error_display_all_variants() {
    assert_eq!(ChainIntegrityError::EmptyStream.to_string(), "empty stream");
    assert_eq!(
        ChainIntegrityError::HeadMismatch.to_string(),
        "chain head mismatch"
    );
    let hash_mismatch = ChainIntegrityError::MarkerHashMismatch {
        marker_id: 42,
        expected: ContentHash([0; 32]),
        computed: ContentHash([1; 32]),
    };
    assert!(hash_mismatch.to_string().contains("42"));
    assert!(hash_mismatch.to_string().contains("hash mismatch"));

    let link_broken = ChainIntegrityError::ChainLinkBroken {
        marker_id: 7,
        expected_prev: ContentHash([0; 32]),
        actual_prev: ContentHash([1; 32]),
    };
    assert!(link_broken.to_string().contains("7"));
    assert!(link_broken.to_string().contains("chain link broken"));

    let non_mono = ChainIntegrityError::NonMonotonicId {
        marker_id: 3,
        prev_marker_id: 5,
    };
    assert!(non_mono.to_string().contains("non-monotonic"));
    assert!(non_mono.to_string().contains("3"));
    assert!(non_mono.to_string().contains("5"));
}

#[test]
fn chain_integrity_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ChainIntegrityError::EmptyStream);
    assert_eq!(err.to_string(), "empty stream");
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

#[test]
fn stress_large_stream_verifies() {
    let mut stream = DecisionMarkerStream::new(50, b"stress-key".to_vec());

    let decision_types = [
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
            from_epoch: 0,
            to_epoch: 1,
        },
        DecisionType::EmergencyOverride {
            override_reason: "stress".into(),
        },
        DecisionType::GuardrailTriggered {
            guardrail_id: "GR-STRESS".into(),
        },
    ];

    for i in 0..500 {
        let dt = decision_types[i % decision_types.len()].clone();
        stream.append(make_input(
            dt,
            &format!("stress-{i}"),
            i as u64,
            i as u64 / 100,
        ));
    }

    assert_eq!(stream.len(), 500);
    assert!(stream.verify_chain().is_ok());
    assert!(stream.verify_head().is_ok());

    // Should have 10 checkpoints (500 / 50).
    assert_eq!(stream.checkpoints().len(), 10);

    // All 500 events should be present.
    let events = stream.drain_events();
    assert_eq!(events.len(), 500);

    // Verify range on a subset.
    assert!(stream.verify_range(100, 200).is_ok());
}

// ---------------------------------------------------------------------------
// DecisionMarker determinism across separate streams
// ---------------------------------------------------------------------------

#[test]
fn identical_inputs_produce_identical_marker_hashes() {
    let mut stream_a = make_stream();
    let mut stream_b = make_stream();

    for i in 0..5 {
        stream_a.append(quarantine_input(&i.to_string()));
        stream_b.append(quarantine_input(&i.to_string()));
    }

    for i in 0..5 {
        assert_eq!(
            stream_a.markers()[i].marker_hash,
            stream_b.markers()[i].marker_hash,
            "hash mismatch at index {i}"
        );
    }
}

#[test]
fn different_inputs_produce_different_marker_hashes() {
    let mut stream = make_stream();
    stream.append(quarantine_input("alpha"));
    stream.append(quarantine_input("beta"));

    assert_ne!(
        stream.markers()[0].marker_hash,
        stream.markers()[1].marker_hash
    );
}

// ---------------------------------------------------------------------------
// is_empty / len
// ---------------------------------------------------------------------------

#[test]
fn empty_stream_properties() {
    let stream = make_stream();
    assert!(stream.is_empty());
    assert_eq!(stream.len(), 0);
    assert!(stream.markers().is_empty());
    assert!(stream.checkpoints().is_empty());
    assert!(stream.chain_head().is_none());
    assert!(stream.get(1).is_none());
    assert!(stream.by_correlation_id("anything").is_empty());
    assert!(stream.by_event_type("anything").is_empty());
    assert!(stream.by_principal_id("anything").is_empty());
    assert!(stream.by_time_range(0, u64::MAX).is_empty());
    assert!(stream.by_error_code("anything").is_empty());
}

#[test]
fn len_and_is_empty_after_appends() {
    let mut stream = make_stream();
    assert!(stream.is_empty());
    stream.append(quarantine_input("1"));
    assert!(!stream.is_empty());
    assert_eq!(stream.len(), 1);
    stream.append(quarantine_input("2"));
    assert_eq!(stream.len(), 2);
}
