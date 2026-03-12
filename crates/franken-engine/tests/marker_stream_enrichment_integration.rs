#![forbid(unsafe_code)]
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
use frankenengine_engine::marker_stream::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn evidence_hash(tag: &str) -> ContentHash {
    ContentHash::compute(format!("evidence-{tag}").as_bytes())
}

fn corr(id: &str) -> CorrelationId {
    CorrelationId::new(id).expect("valid correlation id")
}

fn mk_stream() -> DecisionMarkerStream {
    DecisionMarkerStream::new(5, b"enrichment-key".to_vec())
}

fn mk_input(
    ticks: u64,
    epoch: u64,
    dt: DecisionType,
    suffix: &str,
) -> MarkerInput {
    MarkerInput {
        timestamp_ticks: ticks,
        epoch_id: epoch,
        decision_type: dt,
        decision_id: format!("dec-{suffix}"),
        policy_id: Some(format!("pol-{suffix}")),
        correlation_id: corr(&format!("corr-{suffix}")),
        trace_context: None,
        principal_id: Some(format!("principal-{suffix}")),
        zone_id: Some(format!("zone-{suffix}")),
        error_code: None,
        evidence_entry_hash: evidence_hash(suffix),
        actor: format!("actor-{suffix}"),
        payload_summary: format!("summary-{suffix}"),
        full_payload: None,
        trace_id: format!("trace-{suffix}"),
    }
}

fn quarantine_dt() -> DecisionType {
    DecisionType::SecurityAction {
        action: SecurityActionKind::Quarantine,
    }
}

fn suspend_dt() -> DecisionType {
    DecisionType::SecurityAction {
        action: SecurityActionKind::Suspend,
    }
}

fn terminate_dt() -> DecisionType {
    DecisionType::SecurityAction {
        action: SecurityActionKind::Terminate,
    }
}

fn activation_dt() -> DecisionType {
    DecisionType::PolicyTransition {
        transition: PolicyTransitionKind::Activation,
    }
}

fn deactivation_dt() -> DecisionType {
    DecisionType::PolicyTransition {
        transition: PolicyTransitionKind::Deactivation,
    }
}

fn epoch_advance_dt() -> DecisionType {
    DecisionType::PolicyTransition {
        transition: PolicyTransitionKind::EpochAdvancement,
    }
}

fn issuance_dt() -> DecisionType {
    DecisionType::RevocationEvent {
        revocation: RevocationKind::Issuance,
    }
}

fn propagation_dt() -> DecisionType {
    DecisionType::RevocationEvent {
        revocation: RevocationKind::PropagationConfirmation,
    }
}

fn epoch_transition_dt(from: u64, to: u64) -> DecisionType {
    DecisionType::EpochTransition {
        from_epoch: from,
        to_epoch: to,
    }
}

fn override_dt(reason: &str) -> DecisionType {
    DecisionType::EmergencyOverride {
        override_reason: reason.to_string(),
    }
}

fn guardrail_dt(id: &str) -> DecisionType {
    DecisionType::GuardrailTriggered {
        guardrail_id: id.to_string(),
    }
}

/// Build a stream with N quarantine markers, returning it.
fn stream_with_n_markers(n: usize) -> DecisionMarkerStream {
    let mut stream = mk_stream();
    for i in 0..n {
        stream.append(mk_input(100 + i as u64, 1, quarantine_dt(), &i.to_string()));
    }
    stream
}

// ===========================================================================
// CorrelationId validation edge cases
// ===========================================================================

#[test]
fn enrichment_correlation_id_single_char_accepted() {
    assert!(CorrelationId::new("x").is_ok());
}

#[test]
fn enrichment_correlation_id_all_allowed_chars() {
    // Alphanumeric + dash + underscore + dot
    let id = CorrelationId::new("aZ09-_.").unwrap();
    assert_eq!(id.as_str(), "aZ09-_.");
}

#[test]
fn enrichment_correlation_id_slash_rejected() {
    assert!(CorrelationId::new("a/b").is_err());
}

#[test]
fn enrichment_correlation_id_colon_rejected() {
    assert!(CorrelationId::new("a:b").is_err());
}

#[test]
fn enrichment_correlation_id_unicode_rejected() {
    assert!(CorrelationId::new("hello\u{00e9}").is_err());
}

#[test]
fn enrichment_correlation_id_newline_rejected() {
    assert!(CorrelationId::new("hello\n").is_err());
}

#[test]
fn enrichment_correlation_id_boundary_127_accepted() {
    let s = "a".repeat(127);
    assert!(CorrelationId::new(s).is_ok());
}

#[test]
fn enrichment_correlation_id_boundary_128_accepted() {
    let s = "b".repeat(128);
    let cid = CorrelationId::new(s).unwrap();
    assert_eq!(cid.as_str().len(), 128);
}

#[test]
fn enrichment_correlation_id_boundary_129_rejected() {
    let s = "c".repeat(129);
    assert!(CorrelationId::new(s).is_err());
}

#[test]
fn enrichment_correlation_id_display_equals_as_str() {
    let cid = corr("test-display-parity");
    assert_eq!(cid.to_string(), cid.as_str());
}

#[test]
fn enrichment_correlation_id_ord_lexicographic() {
    let a = corr("aaa");
    let b = corr("aab");
    let c = corr("bbb");
    assert!(a < b);
    assert!(b < c);
    assert!(a < c);
}

#[test]
fn enrichment_correlation_id_serde_roundtrip_preserves_value() {
    let cid = corr("serde-rt-123");
    let json = serde_json::to_string(&cid).unwrap();
    let restored: CorrelationId = serde_json::from_str(&json).unwrap();
    assert_eq!(cid.as_str(), restored.as_str());
    assert_eq!(cid, restored);
}

// ===========================================================================
// SecurityActionKind Display and serde
// ===========================================================================

#[test]
fn enrichment_security_action_kind_display_all_unique() {
    let strs: BTreeSet<String> = [
        SecurityActionKind::Quarantine,
        SecurityActionKind::Suspend,
        SecurityActionKind::Terminate,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(strs.len(), 3);
}

#[test]
fn enrichment_security_action_kind_serde_all_variants() {
    for v in [
        SecurityActionKind::Quarantine,
        SecurityActionKind::Suspend,
        SecurityActionKind::Terminate,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: SecurityActionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// PolicyTransitionKind Display and serde
// ===========================================================================

#[test]
fn enrichment_policy_transition_kind_display_all_unique() {
    let strs: BTreeSet<String> = [
        PolicyTransitionKind::Activation,
        PolicyTransitionKind::Deactivation,
        PolicyTransitionKind::EpochAdvancement,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(strs.len(), 3);
}

#[test]
fn enrichment_policy_transition_kind_serde_all_variants() {
    for v in [
        PolicyTransitionKind::Activation,
        PolicyTransitionKind::Deactivation,
        PolicyTransitionKind::EpochAdvancement,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: PolicyTransitionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// RevocationKind Display and serde
// ===========================================================================

#[test]
fn enrichment_revocation_kind_display_all_unique() {
    let strs: BTreeSet<String> = [
        RevocationKind::Issuance,
        RevocationKind::PropagationConfirmation,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(strs.len(), 2);
}

#[test]
fn enrichment_revocation_kind_serde_all_variants() {
    for v in [
        RevocationKind::Issuance,
        RevocationKind::PropagationConfirmation,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: RevocationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// DecisionType Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_decision_type_display_all_unique() {
    let variants = [
        quarantine_dt(),
        suspend_dt(),
        terminate_dt(),
        activation_dt(),
        deactivation_dt(),
        epoch_advance_dt(),
        issuance_dt(),
        propagation_dt(),
        epoch_transition_dt(1, 2),
        override_dt("reason-a"),
        guardrail_dt("grd-1"),
    ];
    let strs: BTreeSet<String> = variants.iter().map(|d| d.to_string()).collect();
    assert_eq!(strs.len(), variants.len());
}

#[test]
fn enrichment_decision_type_serde_all_variants() {
    let variants = [
        quarantine_dt(),
        suspend_dt(),
        terminate_dt(),
        activation_dt(),
        deactivation_dt(),
        epoch_advance_dt(),
        issuance_dt(),
        propagation_dt(),
        epoch_transition_dt(0, u64::MAX),
        override_dt("critical-override"),
        guardrail_dt("guardrail-99"),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: DecisionType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_decision_type_epoch_transition_display_format() {
    assert_eq!(epoch_transition_dt(10, 20).to_string(), "epoch_transition:10->20");
}

#[test]
fn enrichment_decision_type_emergency_override_omits_reason_in_display() {
    // Display does not include the reason string
    let dt = override_dt("super-secret");
    let s = dt.to_string();
    assert_eq!(s, "emergency_override");
    assert!(!s.contains("super-secret"));
}

#[test]
fn enrichment_decision_type_guardrail_display_includes_id() {
    let dt = guardrail_dt("grd-abc");
    assert_eq!(dt.to_string(), "guardrail_triggered:grd-abc");
}

#[test]
fn enrichment_decision_type_ordering_security_before_policy() {
    assert!(quarantine_dt() < activation_dt());
}

#[test]
fn enrichment_decision_type_ordering_within_security_actions() {
    assert!(quarantine_dt() < suspend_dt());
    assert!(suspend_dt() < terminate_dt());
}

// ===========================================================================
// TraceContext construction and serde
// ===========================================================================

#[test]
fn enrichment_trace_context_all_fields_populated_serde() {
    let tc = TraceContext {
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        tracestate: Some("vendor=value,key=val2".to_string()),
        baggage: Some("tenant=alpha,env=prod".to_string()),
    };
    let json = serde_json::to_string(&tc).unwrap();
    let back: TraceContext = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, back);
}

#[test]
fn enrichment_trace_context_optional_fields_none_serde() {
    let tc = TraceContext {
        traceparent: "00-abc-def-01".to_string(),
        tracestate: None,
        baggage: None,
    };
    let json = serde_json::to_string(&tc).unwrap();
    let back: TraceContext = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, back);
    assert!(json.contains("\"tracestate\":null"));
    assert!(json.contains("\"baggage\":null"));
}

#[test]
fn enrichment_trace_context_clone_independence() {
    let tc = TraceContext {
        traceparent: "original".to_string(),
        tracestate: Some("state".to_string()),
        baggage: Some("bag".to_string()),
    };
    let mut cloned = tc.clone();
    cloned.traceparent = "mutated".to_string();
    cloned.tracestate = None;
    assert_eq!(tc.traceparent, "original");
    assert!(tc.tracestate.is_some());
}

// ===========================================================================
// RedactedPayload construction and serde
// ===========================================================================

#[test]
fn enrichment_redacted_payload_with_redaction_serde() {
    let rp = RedactedPayload {
        redacted_summary: "[redacted]".to_string(),
        payload_hash: ContentHash::compute(b"full-secret-payload"),
        redaction_applied: true,
    };
    let json = serde_json::to_string(&rp).unwrap();
    let back: RedactedPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(rp, back);
    assert!(!json.contains("full-secret-payload"));
}

#[test]
fn enrichment_redacted_payload_without_redaction_serde() {
    let rp = RedactedPayload {
        redacted_summary: "benign summary".to_string(),
        payload_hash: ContentHash::compute(b"benign summary"),
        redaction_applied: false,
    };
    let json = serde_json::to_string(&rp).unwrap();
    let back: RedactedPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(rp, back);
}

// ===========================================================================
// ChainIntegrityError Display uniqueness and std::error::Error
// ===========================================================================

#[test]
fn enrichment_chain_integrity_error_display_all_unique() {
    let zero = ContentHash([0u8; 32]);
    let one = ContentHash([1u8; 32]);
    let errors = [
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
            marker_id: 3,
            prev_marker_id: 5,
        },
        ChainIntegrityError::HeadMismatch,
    ];
    let strs: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(strs.len(), errors.len());
}

#[test]
fn enrichment_chain_integrity_error_is_std_error_for_all_variants() {
    let zero = ContentHash([0u8; 32]);
    let one = ContentHash([1u8; 32]);
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(ChainIntegrityError::MarkerHashMismatch {
            marker_id: 1,
            expected: zero,
            computed: one,
        }),
        Box::new(ChainIntegrityError::ChainLinkBroken {
            marker_id: 2,
            expected_prev: zero,
            actual_prev: one,
        }),
        Box::new(ChainIntegrityError::EmptyStream),
        Box::new(ChainIntegrityError::NonMonotonicId {
            marker_id: 3,
            prev_marker_id: 5,
        }),
        Box::new(ChainIntegrityError::HeadMismatch),
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn enrichment_chain_integrity_error_serde_all_variants() {
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
            marker_id: 3,
            prev_marker_id: 5,
        },
        ChainIntegrityError::HeadMismatch,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ChainIntegrityError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_chain_integrity_error_marker_hash_mismatch_display_contains_id() {
    let e = ChainIntegrityError::MarkerHashMismatch {
        marker_id: 77,
        expected: ContentHash([0u8; 32]),
        computed: ContentHash([1u8; 32]),
    };
    let s = e.to_string();
    assert!(s.contains("77"));
    assert!(s.contains("hash mismatch"));
}

#[test]
fn enrichment_chain_integrity_error_chain_link_broken_display_contains_id() {
    let e = ChainIntegrityError::ChainLinkBroken {
        marker_id: 88,
        expected_prev: ContentHash([0u8; 32]),
        actual_prev: ContentHash([1u8; 32]),
    };
    let s = e.to_string();
    assert!(s.contains("88"));
    assert!(s.contains("chain link broken"));
}

#[test]
fn enrichment_chain_integrity_error_non_monotonic_display() {
    let e = ChainIntegrityError::NonMonotonicId {
        marker_id: 5,
        prev_marker_id: 10,
    };
    assert_eq!(e.to_string(), "non-monotonic: 5 after 10");
}

// ===========================================================================
// IntegrityCheckpoint serde and field validation
// ===========================================================================

#[test]
fn enrichment_integrity_checkpoint_serde_roundtrip() {
    let cp = IntegrityCheckpoint {
        at_marker_id: 100,
        marker_hash: ContentHash::compute(b"marker-hash-test"),
        chain_length: 100,
        signed_hash: AuthenticityHash::compute_keyed(b"key", b"checkpoint-data"),
    };
    let json = serde_json::to_string(&cp).unwrap();
    let back: IntegrityCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(cp, back);
}

#[test]
fn enrichment_integrity_checkpoint_signed_hash_is_nonzero() {
    let mut stream = DecisionMarkerStream::new(3, b"checkpoint-key".to_vec());
    for i in 0..3 {
        stream.append(mk_input(100 + i, 1, quarantine_dt(), &i.to_string()));
    }
    assert_eq!(stream.checkpoints().len(), 1);
    let cp = &stream.checkpoints()[0];
    assert_ne!(cp.signed_hash.as_bytes(), &[0u8; 32]);
}

// ===========================================================================
// AuditChainHead serde
// ===========================================================================

#[test]
fn enrichment_audit_chain_head_serde_roundtrip() {
    let head = AuditChainHead {
        head_marker_id: 42,
        latest_marker_hash: ContentHash::compute(b"latest-marker"),
        rolling_chain_hash: ContentHash::compute(b"rolling-hash"),
        signed_head_hash: AuthenticityHash::compute_keyed(b"key", b"head-data"),
    };
    let json = serde_json::to_string(&head).unwrap();
    let back: AuditChainHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, back);
}

#[test]
fn enrichment_audit_chain_head_json_field_presence() {
    let head = AuditChainHead {
        head_marker_id: 1,
        latest_marker_hash: ContentHash([0u8; 32]),
        rolling_chain_hash: ContentHash([0u8; 32]),
        signed_head_hash: AuthenticityHash([0u8; 32]),
    };
    let json = serde_json::to_string(&head).unwrap();
    for field in &[
        "head_marker_id",
        "latest_marker_hash",
        "rolling_chain_hash",
        "signed_head_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// MarkerEvent serde and field checks
// ===========================================================================

#[test]
fn enrichment_marker_event_serde_roundtrip_with_error_code() {
    let ev = MarkerEvent {
        marker_id: 5,
        marker_type: "security_action:quarantine".to_string(),
        chain_length: 5,
        decision_id: "dec-5".to_string(),
        policy_id: Some("pol-active".to_string()),
        principal_id: Some("principal-admin".to_string()),
        correlation_id: "corr-flow-1".to_string(),
        trace_id: "trace-flow-1".to_string(),
        component: "marker_stream".to_string(),
        event: "marker_appended".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("FE-QUARANTINE-001".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: MarkerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_marker_event_serde_roundtrip_without_optional_fields() {
    let ev = MarkerEvent {
        marker_id: 1,
        marker_type: "emergency_override".to_string(),
        chain_length: 1,
        decision_id: "dec-override".to_string(),
        policy_id: None,
        principal_id: None,
        correlation_id: "corr-override".to_string(),
        trace_id: "trace-override".to_string(),
        component: "marker_stream".to_string(),
        event: "marker_appended".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: MarkerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// DecisionMarker serde roundtrip
// ===========================================================================

#[test]
fn enrichment_decision_marker_serde_roundtrip_with_trace_context() {
    let mut stream = mk_stream();
    let mut input = mk_input(500, 3, issuance_dt(), "tc");
    input.trace_context = Some(TraceContext {
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        tracestate: Some("vendor=v".to_string()),
        baggage: Some("tenant=beta".to_string()),
    });
    stream.append(input);
    let marker = &stream.markers()[0];
    let json = serde_json::to_string(marker).unwrap();
    let back: DecisionMarker = serde_json::from_str(&json).unwrap();
    assert_eq!(*marker, back);
}

#[test]
fn enrichment_decision_marker_serde_roundtrip_minimal_fields() {
    let mut stream = mk_stream();
    let input = MarkerInput {
        timestamp_ticks: 0,
        epoch_id: 0,
        decision_type: quarantine_dt(),
        decision_id: "d".to_string(),
        policy_id: None,
        correlation_id: corr("c"),
        trace_context: None,
        principal_id: None,
        zone_id: None,
        error_code: None,
        evidence_entry_hash: ContentHash([0u8; 32]),
        actor: "a".to_string(),
        payload_summary: "s".to_string(),
        full_payload: None,
        trace_id: "t".to_string(),
    };
    stream.append(input);
    let marker = &stream.markers()[0];
    let json = serde_json::to_string(marker).unwrap();
    let back: DecisionMarker = serde_json::from_str(&json).unwrap();
    assert_eq!(*marker, back);
}

// ===========================================================================
// Stream: append, len, is_empty, get
// ===========================================================================

#[test]
fn enrichment_stream_empty_initially() {
    let stream = mk_stream();
    assert!(stream.is_empty());
    assert_eq!(stream.len(), 0);
    assert!(stream.markers().is_empty());
    assert!(stream.checkpoints().is_empty());
    assert!(stream.chain_head().is_none());
}

#[test]
fn enrichment_stream_append_increments_len() {
    let mut stream = mk_stream();
    for i in 1..=10 {
        stream.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
        assert_eq!(stream.len(), i as usize);
        assert!(!stream.is_empty());
    }
}

#[test]
fn enrichment_stream_marker_ids_monotonically_increase() {
    let stream = stream_with_n_markers(20);
    let ids: Vec<u64> = stream.markers().iter().map(|m| m.marker_id).collect();
    for pair in ids.windows(2) {
        assert!(pair[0] < pair[1]);
    }
}

#[test]
fn enrichment_stream_get_returns_correct_marker() {
    let stream = stream_with_n_markers(5);
    for i in 1..=5u64 {
        let m = stream.get(i).unwrap();
        assert_eq!(m.marker_id, i);
    }
}

#[test]
fn enrichment_stream_get_nonexistent_returns_none() {
    let stream = stream_with_n_markers(3);
    assert!(stream.get(0).is_none());
    assert!(stream.get(4).is_none());
    assert!(stream.get(999).is_none());
}

// ===========================================================================
// Hash chain integrity
// ===========================================================================

#[test]
fn enrichment_genesis_marker_has_zero_prev_hash() {
    let stream = stream_with_n_markers(1);
    assert_eq!(stream.markers()[0].prev_marker_hash, ContentHash([0u8; 32]));
}

#[test]
fn enrichment_subsequent_markers_chain_correctly() {
    let stream = stream_with_n_markers(10);
    for i in 1..stream.markers().len() {
        assert_eq!(
            stream.markers()[i].prev_marker_hash,
            stream.markers()[i - 1].marker_hash
        );
    }
}

#[test]
fn enrichment_marker_hash_is_nonzero() {
    let stream = stream_with_n_markers(1);
    assert_ne!(stream.markers()[0].marker_hash, ContentHash([0u8; 32]));
}

#[test]
fn enrichment_different_inputs_produce_different_hashes() {
    let mut stream = mk_stream();
    stream.append(mk_input(100, 1, quarantine_dt(), "alpha"));
    stream.append(mk_input(200, 2, suspend_dt(), "beta"));
    assert_ne!(
        stream.markers()[0].marker_hash,
        stream.markers()[1].marker_hash
    );
}

#[test]
fn enrichment_deterministic_hashes_across_runs() {
    let run = || {
        let mut s = DecisionMarkerStream::new(5, b"det-key".to_vec());
        s.append(mk_input(100, 1, quarantine_dt(), "det-1"));
        s.append(mk_input(200, 2, activation_dt(), "det-2"));
        s.append(mk_input(300, 3, epoch_transition_dt(1, 3), "det-3"));
        s.markers()
            .iter()
            .map(|m| m.marker_hash)
            .collect::<Vec<_>>()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// verify_chain
// ===========================================================================

#[test]
fn enrichment_verify_chain_succeeds_valid_stream() {
    let stream = stream_with_n_markers(15);
    assert!(stream.verify_chain().is_ok());
}

#[test]
fn enrichment_verify_chain_empty_stream_error() {
    let stream = mk_stream();
    let err = stream.verify_chain().unwrap_err();
    assert!(matches!(err, ChainIntegrityError::EmptyStream));
}

#[test]
fn enrichment_verify_chain_single_marker_succeeds() {
    let stream = stream_with_n_markers(1);
    assert!(stream.verify_chain().is_ok());
}

// ===========================================================================
// verify_range
// ===========================================================================

#[test]
fn enrichment_verify_range_valid_subrange() {
    let stream = stream_with_n_markers(10);
    assert!(stream.verify_range(3, 7).is_ok());
}

#[test]
fn enrichment_verify_range_single_marker() {
    let stream = stream_with_n_markers(5);
    assert!(stream.verify_range(3, 3).is_ok());
}

#[test]
fn enrichment_verify_range_full_range() {
    let stream = stream_with_n_markers(5);
    assert!(stream.verify_range(1, 5).is_ok());
}

#[test]
fn enrichment_verify_range_nonexistent_from_id() {
    let stream = stream_with_n_markers(5);
    let result = stream.verify_range(99, 3);
    assert!(result.is_err());
}

#[test]
fn enrichment_verify_range_nonexistent_to_id() {
    let stream = stream_with_n_markers(5);
    let result = stream.verify_range(1, 99);
    assert!(result.is_err());
}

// ===========================================================================
// verify_head
// ===========================================================================

#[test]
fn enrichment_verify_head_empty_stream_ok() {
    let stream = mk_stream();
    assert!(stream.verify_head().is_ok());
}

#[test]
fn enrichment_verify_head_after_single_append() {
    let stream = stream_with_n_markers(1);
    assert!(stream.verify_head().is_ok());
}

#[test]
fn enrichment_verify_head_after_many_appends() {
    let stream = stream_with_n_markers(20);
    assert!(stream.verify_head().is_ok());
}

#[test]
fn enrichment_chain_head_advances_with_each_append() {
    let mut stream = mk_stream();
    stream.append(mk_input(1, 1, quarantine_dt(), "h1"));
    let head1 = stream.chain_head().unwrap().head_marker_id;
    stream.append(mk_input(2, 1, suspend_dt(), "h2"));
    let head2 = stream.chain_head().unwrap().head_marker_id;
    stream.append(mk_input(3, 1, terminate_dt(), "h3"));
    let head3 = stream.chain_head().unwrap().head_marker_id;
    assert!(head1 < head2);
    assert!(head2 < head3);
}

#[test]
fn enrichment_chain_head_rolling_hash_changes_with_appends() {
    let mut stream = mk_stream();
    stream.append(mk_input(1, 1, quarantine_dt(), "r1"));
    let rolling1 = stream.chain_head().unwrap().rolling_chain_hash;
    stream.append(mk_input(2, 1, suspend_dt(), "r2"));
    let rolling2 = stream.chain_head().unwrap().rolling_chain_hash;
    assert_ne!(rolling1, rolling2);
}

// ===========================================================================
// Checkpoints
// ===========================================================================

#[test]
fn enrichment_checkpoint_emitted_at_correct_intervals() {
    let mut stream = DecisionMarkerStream::new(3, b"cp-key".to_vec());
    for i in 0..9 {
        stream.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
    }
    // Checkpoints at markers 3, 6, 9
    assert_eq!(stream.checkpoints().len(), 3);
    assert_eq!(stream.checkpoints()[0].at_marker_id, 3);
    assert_eq!(stream.checkpoints()[1].at_marker_id, 6);
    assert_eq!(stream.checkpoints()[2].at_marker_id, 9);
}

#[test]
fn enrichment_checkpoint_chain_length_matches_stream_at_emission() {
    let mut stream = DecisionMarkerStream::new(4, b"cp-len-key".to_vec());
    for i in 0..8 {
        stream.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
    }
    assert_eq!(stream.checkpoints().len(), 2);
    assert_eq!(stream.checkpoints()[0].chain_length, 4);
    assert_eq!(stream.checkpoints()[1].chain_length, 8);
}

#[test]
fn enrichment_checkpoint_marker_hash_matches_marker_at_position() {
    let mut stream = DecisionMarkerStream::new(3, b"cp-hash-key".to_vec());
    for i in 0..3 {
        stream.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
    }
    let cp = &stream.checkpoints()[0];
    let marker = stream.get(cp.at_marker_id).unwrap();
    assert_eq!(cp.marker_hash, marker.marker_hash);
}

#[test]
fn enrichment_no_checkpoint_when_interval_zero() {
    let mut stream = DecisionMarkerStream::new(0, b"no-cp".to_vec());
    for i in 0..10 {
        stream.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
    }
    assert!(stream.checkpoints().is_empty());
}

#[test]
fn enrichment_checkpoint_deterministic_across_runs() {
    let run = || {
        let mut s = DecisionMarkerStream::new(2, b"det-cp".to_vec());
        for i in 0..4 {
            s.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
        }
        s.checkpoints().to_vec()
    };
    let cp1 = run();
    let cp2 = run();
    assert_eq!(cp1, cp2);
}

#[test]
fn enrichment_different_keys_produce_different_signed_checkpoints() {
    let build = |key: &[u8]| {
        let mut s = DecisionMarkerStream::new(1, key.to_vec());
        s.append(mk_input(1, 1, quarantine_dt(), "key-test"));
        s.checkpoints()[0].signed_hash
    };
    let sig_a = build(b"key-alpha");
    let sig_b = build(b"key-beta");
    assert_ne!(sig_a, sig_b);
}

// ===========================================================================
// Query methods: by_correlation_id, by_event_type, by_principal_id,
//                by_time_range, by_error_code
// ===========================================================================

#[test]
fn enrichment_by_correlation_id_groups_related_markers() {
    let mut stream = mk_stream();
    // Two markers with same correlation, one different
    let mut input_a1 = mk_input(100, 1, quarantine_dt(), "ca1");
    input_a1.correlation_id = corr("flow-alpha");
    let mut input_a2 = mk_input(200, 1, suspend_dt(), "ca2");
    input_a2.correlation_id = corr("flow-alpha");
    let mut input_b = mk_input(300, 1, terminate_dt(), "cb1");
    input_b.correlation_id = corr("flow-beta");
    stream.append(input_a1);
    stream.append(input_a2);
    stream.append(input_b);

    assert_eq!(stream.by_correlation_id("flow-alpha").len(), 2);
    assert_eq!(stream.by_correlation_id("flow-beta").len(), 1);
    assert!(stream.by_correlation_id("flow-gamma").is_empty());
}

#[test]
fn enrichment_by_event_type_filters_correctly() {
    let mut stream = mk_stream();
    stream.append(mk_input(100, 1, quarantine_dt(), "et1"));
    stream.append(mk_input(200, 1, activation_dt(), "et2"));
    stream.append(mk_input(300, 1, quarantine_dt(), "et3"));

    let quarantines = stream.by_event_type("security_action:quarantine");
    assert_eq!(quarantines.len(), 2);
    let activations = stream.by_event_type("policy_transition:activation");
    assert_eq!(activations.len(), 1);
    assert!(stream.by_event_type("nonexistent").is_empty());
}

#[test]
fn enrichment_by_principal_id_returns_matching() {
    let mut stream = mk_stream();
    stream.append(mk_input(100, 1, quarantine_dt(), "p1"));
    stream.append(mk_input(200, 1, suspend_dt(), "p2"));
    // Both have principal_id = Some("principal-p1") / Some("principal-p2")
    assert_eq!(stream.by_principal_id("principal-p1").len(), 1);
    assert_eq!(stream.by_principal_id("principal-p2").len(), 1);
    assert!(stream.by_principal_id("nonexistent").is_empty());
}

#[test]
fn enrichment_by_principal_id_skips_none_principal() {
    let mut stream = mk_stream();
    let mut input = mk_input(100, 1, quarantine_dt(), "np");
    input.principal_id = None;
    stream.append(input);
    assert!(stream.by_principal_id("principal-np").is_empty());
}

#[test]
fn enrichment_by_time_range_inclusive_boundaries() {
    let mut stream = mk_stream();
    stream.append(mk_input(100, 1, quarantine_dt(), "t0"));
    stream.append(mk_input(200, 1, suspend_dt(), "t1"));
    stream.append(mk_input(300, 1, terminate_dt(), "t2"));
    stream.append(mk_input(400, 1, activation_dt(), "t3"));

    // Exactly [200, 300] -- inclusive
    let range = stream.by_time_range(200, 300);
    assert_eq!(range.len(), 2);
    assert_eq!(range[0].timestamp_ticks, 200);
    assert_eq!(range[1].timestamp_ticks, 300);
}

#[test]
fn enrichment_by_time_range_empty_when_no_overlap() {
    let stream = stream_with_n_markers(5); // ticks: 100..104
    assert!(stream.by_time_range(500, 600).is_empty());
}

#[test]
fn enrichment_by_time_range_single_tick_match() {
    let stream = stream_with_n_markers(3); // ticks: 100, 101, 102
    let range = stream.by_time_range(101, 101);
    assert_eq!(range.len(), 1);
    assert_eq!(range[0].timestamp_ticks, 101);
}

#[test]
fn enrichment_by_error_code_filters_matching() {
    let mut stream = mk_stream();
    let mut input_with_err = mk_input(100, 1, quarantine_dt(), "err1");
    input_with_err.error_code = Some("FE-SEC-001".to_string());
    let input_no_err = mk_input(200, 1, suspend_dt(), "err2");
    let mut input_other_err = mk_input(300, 1, terminate_dt(), "err3");
    input_other_err.error_code = Some("FE-SEC-002".to_string());
    stream.append(input_with_err);
    stream.append(input_no_err);
    stream.append(input_other_err);

    assert_eq!(stream.by_error_code("FE-SEC-001").len(), 1);
    assert_eq!(stream.by_error_code("FE-SEC-002").len(), 1);
    assert!(stream.by_error_code("FE-SEC-999").is_empty());
}

// ===========================================================================
// Events: drain_events
// ===========================================================================

#[test]
fn enrichment_drain_events_returns_one_event_per_append() {
    let mut stream = mk_stream();
    stream.append(mk_input(1, 1, quarantine_dt(), "ev1"));
    stream.append(mk_input(2, 1, suspend_dt(), "ev2"));
    stream.append(mk_input(3, 1, terminate_dt(), "ev3"));
    let events = stream.drain_events();
    assert_eq!(events.len(), 3);
}

#[test]
fn enrichment_drain_events_clears_after_drain() {
    let mut stream = mk_stream();
    stream.append(mk_input(1, 1, quarantine_dt(), "clr1"));
    let ev1 = stream.drain_events();
    assert_eq!(ev1.len(), 1);
    let ev2 = stream.drain_events();
    assert!(ev2.is_empty());
}

#[test]
fn enrichment_event_fields_match_input() {
    let mut stream = mk_stream();
    let mut input = mk_input(500, 7, activation_dt(), "match");
    input.error_code = Some("FE-MATCH-001".to_string());
    stream.append(input);
    let events = stream.drain_events();
    let ev = &events[0];
    assert_eq!(ev.marker_id, 1);
    assert_eq!(ev.chain_length, 1);
    assert_eq!(ev.decision_id, "dec-match");
    assert_eq!(ev.policy_id.as_deref(), Some("pol-match"));
    assert_eq!(ev.principal_id.as_deref(), Some("principal-match"));
    assert_eq!(ev.correlation_id, "corr-match");
    assert_eq!(ev.trace_id, "trace-match");
    assert_eq!(ev.component, "marker_stream");
    assert_eq!(ev.event, "marker_appended");
    assert_eq!(ev.outcome, "ok");
    assert_eq!(ev.error_code.as_deref(), Some("FE-MATCH-001"));
}

#[test]
fn enrichment_event_marker_type_matches_decision_type_display() {
    let mut stream = mk_stream();
    stream.append(mk_input(1, 1, epoch_transition_dt(5, 6), "etd"));
    let events = stream.drain_events();
    assert_eq!(events[0].marker_type, "epoch_transition:5->6");
}

// ===========================================================================
// Redacted payload behavior
// ===========================================================================

#[test]
fn enrichment_redaction_applied_when_full_payload_present() {
    let mut stream = mk_stream();
    let mut input = mk_input(100, 1, quarantine_dt(), "redact1");
    input.full_payload = Some("secret-data-do-not-store".to_string());
    input.payload_summary = "[redacted]".to_string();
    stream.append(input);
    let marker = stream.get(1).unwrap();
    assert!(marker.redacted_payload.redaction_applied);
    assert_eq!(marker.redacted_payload.redacted_summary, "[redacted]");
    // The hash should be of the full payload
    assert_eq!(
        marker.redacted_payload.payload_hash,
        ContentHash::compute(b"secret-data-do-not-store")
    );
}

#[test]
fn enrichment_no_redaction_when_full_payload_absent() {
    let mut stream = mk_stream();
    let mut input = mk_input(100, 1, quarantine_dt(), "no-redact");
    input.full_payload = None;
    input.payload_summary = "plain summary".to_string();
    stream.append(input);
    let marker = stream.get(1).unwrap();
    assert!(!marker.redacted_payload.redaction_applied);
    // The hash is of the summary itself
    assert_eq!(
        marker.redacted_payload.payload_hash,
        ContentHash::compute(b"plain summary")
    );
}

#[test]
fn enrichment_redacted_summary_never_contains_full_payload() {
    let mut stream = mk_stream();
    let mut input = mk_input(100, 1, quarantine_dt(), "secret-test");
    input.full_payload = Some("SUPER_SECRET_TOKEN_12345".to_string());
    input.payload_summary = "[REDACTED]".to_string();
    stream.append(input);
    let marker = stream.get(1).unwrap();
    assert!(!marker.redacted_payload.redacted_summary.contains("SUPER_SECRET_TOKEN_12345"));
}

// ===========================================================================
// Cross-cutting integration: multi-decision-type flow with full verification
// ===========================================================================

#[test]
fn enrichment_multi_type_flow_with_shared_correlation() {
    let mut stream = DecisionMarkerStream::new(3, b"flow-key".to_vec());
    let shared_corr = corr("flow-incident-42");

    // Simulate an incident response flow
    let flow = [
        (100, 1, quarantine_dt(), "quarantine target"),
        (101, 1, issuance_dt(), "revoke cert"),
        (102, 1, propagation_dt(), "propagation confirmed"),
        (103, 1, override_dt("operator approved escalation"), "escalate"),
        (104, 2, epoch_transition_dt(1, 2), "advance epoch"),
        (105, 2, activation_dt(), "activate new policy"),
    ];

    for (i, (ticks, epoch, dt, summary)) in flow.iter().enumerate() {
        let mut input = mk_input(*ticks, *epoch, dt.clone(), &format!("flow-{i}"));
        input.correlation_id = shared_corr.clone();
        input.payload_summary = summary.to_string();
        stream.append(input);
    }

    // All 6 markers share the correlation
    assert_eq!(stream.by_correlation_id("flow-incident-42").len(), 6);

    // Chain integrity holds
    assert!(stream.verify_chain().is_ok());
    assert!(stream.verify_head().is_ok());

    // 2 checkpoints emitted (at markers 3 and 6)
    assert_eq!(stream.checkpoints().len(), 2);

    // Events emitted for each append
    let events = stream.drain_events();
    assert_eq!(events.len(), 6);
    for ev in &events {
        assert_eq!(ev.correlation_id, "flow-incident-42");
    }
}

#[test]
fn enrichment_multi_principal_multi_zone_stream() {
    let mut stream = mk_stream();
    let principals = ["admin", "operator", "system"];
    let zones = ["zone-a", "zone-b", "zone-c"];

    for (i, (principal, zone)) in principals.iter().zip(zones.iter()).enumerate() {
        let mut input = mk_input(i as u64, 1, quarantine_dt(), &format!("mpz-{i}"));
        input.principal_id = Some(principal.to_string());
        input.zone_id = Some(zone.to_string());
        stream.append(input);
    }

    assert_eq!(stream.by_principal_id("admin").len(), 1);
    assert_eq!(stream.by_principal_id("operator").len(), 1);
    assert_eq!(stream.by_principal_id("system").len(), 1);
    assert!(stream.verify_chain().is_ok());
}

#[test]
fn enrichment_large_stream_verification() {
    let stream = stream_with_n_markers(100);
    assert_eq!(stream.len(), 100);
    assert!(stream.verify_chain().is_ok());
    assert!(stream.verify_head().is_ok());
    // With checkpoint_interval=5, expect 20 checkpoints
    assert_eq!(stream.checkpoints().len(), 20);
}

#[test]
fn enrichment_stream_with_all_decision_types_verifies() {
    let mut stream = mk_stream();
    let types = [
        quarantine_dt(),
        suspend_dt(),
        terminate_dt(),
        activation_dt(),
        deactivation_dt(),
        epoch_advance_dt(),
        issuance_dt(),
        propagation_dt(),
        epoch_transition_dt(1, 2),
        override_dt("reason"),
        guardrail_dt("grd-x"),
    ];
    for (i, dt) in types.into_iter().enumerate() {
        stream.append(mk_input(i as u64, 1, dt, &format!("all-{i}")));
    }
    assert_eq!(stream.len(), 11);
    assert!(stream.verify_chain().is_ok());
    assert!(stream.verify_head().is_ok());
}

#[test]
fn enrichment_by_event_type_across_all_decision_types() {
    let mut stream = mk_stream();
    let types_and_displays = [
        (quarantine_dt(), "security_action:quarantine"),
        (suspend_dt(), "security_action:suspend"),
        (terminate_dt(), "security_action:terminate"),
        (activation_dt(), "policy_transition:activation"),
        (deactivation_dt(), "policy_transition:deactivation"),
        (epoch_advance_dt(), "policy_transition:epoch_advancement"),
        (issuance_dt(), "revocation_event:issuance"),
        (propagation_dt(), "revocation_event:propagation_confirmation"),
        (epoch_transition_dt(1, 2), "epoch_transition:1->2"),
        (override_dt("r"), "emergency_override"),
        (guardrail_dt("g"), "guardrail_triggered:g"),
    ];
    for (i, (dt, _)) in types_and_displays.iter().enumerate() {
        stream.append(mk_input(i as u64, 1, dt.clone(), &format!("etype-{i}")));
    }
    for (_, display) in &types_and_displays {
        let results = stream.by_event_type(display);
        assert_eq!(results.len(), 1, "expected 1 match for event_type={display}");
    }
}

#[test]
fn enrichment_trace_context_affects_marker_hash() {
    let mut stream_no_tc = mk_stream();
    let input_no_tc = mk_input(100, 1, quarantine_dt(), "notc");
    stream_no_tc.append(input_no_tc);

    let mut stream_tc = mk_stream();
    let mut input_tc = mk_input(100, 1, quarantine_dt(), "notc");
    input_tc.trace_context = Some(TraceContext {
        traceparent: "00-abc-def-01".to_string(),
        tracestate: None,
        baggage: None,
    });
    stream_tc.append(input_tc);

    assert_ne!(
        stream_no_tc.markers()[0].marker_hash,
        stream_tc.markers()[0].marker_hash,
        "trace context presence should change the marker hash"
    );
}

#[test]
fn enrichment_error_code_presence_affects_marker_hash() {
    let mut stream_no_err = mk_stream();
    let input_no_err = mk_input(100, 1, quarantine_dt(), "noerr");
    stream_no_err.append(input_no_err);

    let mut stream_err = mk_stream();
    let mut input_err = mk_input(100, 1, quarantine_dt(), "noerr");
    input_err.error_code = Some("FE-ERR-001".to_string());
    stream_err.append(input_err);

    assert_ne!(
        stream_no_err.markers()[0].marker_hash,
        stream_err.markers()[0].marker_hash,
        "error code presence should change the marker hash"
    );
}

#[test]
fn enrichment_zone_id_affects_marker_hash() {
    let mut stream_a = mk_stream();
    let mut input_a = mk_input(100, 1, quarantine_dt(), "za");
    input_a.zone_id = Some("zone-alpha".to_string());
    stream_a.append(input_a);

    let mut stream_b = mk_stream();
    let mut input_b = mk_input(100, 1, quarantine_dt(), "za");
    input_b.zone_id = Some("zone-beta".to_string());
    stream_b.append(input_b);

    assert_ne!(
        stream_a.markers()[0].marker_hash,
        stream_b.markers()[0].marker_hash
    );
}

#[test]
fn enrichment_checkpoint_interval_one_emits_every_marker() {
    let mut stream = DecisionMarkerStream::new(1, b"every-marker".to_vec());
    for i in 0..5 {
        stream.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
    }
    assert_eq!(stream.checkpoints().len(), 5);
    for (i, cp) in stream.checkpoints().iter().enumerate() {
        assert_eq!(cp.at_marker_id, (i + 1) as u64);
    }
}

#[test]
fn enrichment_verify_range_first_marker_only() {
    let stream = stream_with_n_markers(5);
    assert!(stream.verify_range(1, 1).is_ok());
}

#[test]
fn enrichment_verify_range_last_marker_only() {
    let stream = stream_with_n_markers(5);
    assert!(stream.verify_range(5, 5).is_ok());
}

#[test]
fn enrichment_events_chain_length_increments_per_append() {
    let mut stream = mk_stream();
    for i in 0..5 {
        stream.append(mk_input(i, 1, quarantine_dt(), &i.to_string()));
    }
    let events = stream.drain_events();
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.chain_length, (i + 1) as u64);
    }
}

#[test]
fn enrichment_multiple_error_codes_across_stream() {
    let mut stream = mk_stream();
    let codes = ["FE-A-001", "FE-B-002", "FE-A-001", "FE-C-003"];
    for (i, code) in codes.iter().enumerate() {
        let mut input = mk_input(i as u64, 1, quarantine_dt(), &format!("ec-{i}"));
        input.error_code = Some(code.to_string());
        stream.append(input);
    }
    assert_eq!(stream.by_error_code("FE-A-001").len(), 2);
    assert_eq!(stream.by_error_code("FE-B-002").len(), 1);
    assert_eq!(stream.by_error_code("FE-C-003").len(), 1);
}

#[test]
fn enrichment_rolling_hash_distinct_from_individual_marker_hashes() {
    let stream = stream_with_n_markers(3);
    let head = stream.chain_head().unwrap();
    for m in stream.markers() {
        assert_ne!(head.rolling_chain_hash, m.marker_hash);
    }
}

#[test]
fn enrichment_different_checkpoint_keys_different_chain_head_signatures() {
    let build = |key: &[u8]| {
        let mut s = DecisionMarkerStream::new(5, key.to_vec());
        s.append(mk_input(1, 1, quarantine_dt(), "key-diff"));
        s.chain_head().unwrap().signed_head_hash
    };
    let sig_a = build(b"key-one");
    let sig_b = build(b"key-two");
    assert_ne!(sig_a, sig_b);
}

#[test]
fn enrichment_decision_type_clone_preserves_inner_data() {
    let dt = override_dt("cloned-reason");
    let cloned = dt.clone();
    if let DecisionType::EmergencyOverride { override_reason } = &cloned {
        assert_eq!(override_reason, "cloned-reason");
    } else {
        panic!("expected EmergencyOverride");
    }
    assert_eq!(dt, cloned);
}

#[test]
fn enrichment_guardrail_with_special_characters_in_id() {
    let dt = guardrail_dt("grd-special_name.v2");
    assert_eq!(dt.to_string(), "guardrail_triggered:grd-special_name.v2");
    let json = serde_json::to_string(&dt).unwrap();
    let back: DecisionType = serde_json::from_str(&json).unwrap();
    assert_eq!(dt, back);
}

#[test]
fn enrichment_epoch_transition_boundary_values() {
    let dt = epoch_transition_dt(0, u64::MAX);
    let s = dt.to_string();
    assert!(s.contains("0"));
    assert!(s.contains(&u64::MAX.to_string()));
    let json = serde_json::to_string(&dt).unwrap();
    let back: DecisionType = serde_json::from_str(&json).unwrap();
    assert_eq!(dt, back);
}

#[test]
fn enrichment_decision_marker_json_field_presence_comprehensive() {
    let mut stream = mk_stream();
    let mut input = mk_input(100, 5, quarantine_dt(), "fields");
    input.trace_context = Some(TraceContext {
        traceparent: "tp".to_string(),
        tracestate: None,
        baggage: None,
    });
    input.error_code = Some("FE-001".to_string());
    stream.append(input);
    let json = serde_json::to_string(&stream.markers()[0]).unwrap();
    let required_fields = [
        "marker_id",
        "prev_marker_hash",
        "marker_hash",
        "timestamp_ticks",
        "epoch_id",
        "decision_type",
        "decision_id",
        "policy_id",
        "correlation_id",
        "trace_context",
        "principal_id",
        "zone_id",
        "error_code",
        "evidence_entry_hash",
        "actor",
        "redacted_payload",
    ];
    for field in &required_fields {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_stream_markers_returns_slice_in_append_order() {
    let mut stream = mk_stream();
    let suffixes = ["alpha", "beta", "gamma", "delta"];
    for s in &suffixes {
        stream.append(mk_input(1, 1, quarantine_dt(), s));
    }
    for (i, m) in stream.markers().iter().enumerate() {
        assert_eq!(m.decision_id, format!("dec-{}", suffixes[i]));
    }
}
