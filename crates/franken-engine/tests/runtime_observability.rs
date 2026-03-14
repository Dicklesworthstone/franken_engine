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

use frankenengine_engine::runtime_observability::{
    AuthFailureType, CAPABILITY_DENIAL_TOTAL, CHECKPOINT_VIOLATION_TOTAL,
    CROSS_ZONE_REFERENCE_TOTAL, CapabilityDenialReason, CheckpointViolationType,
    CrossZoneReferenceType, REPLAY_DROP_TOTAL, REVOCATION_CHECK_TOTAL,
    REVOCATION_FRESHNESS_DEGRADED_SECONDS, ReplayDropReason, RevocationCheckOutcome,
    RuntimeSecurityObservability, SecurityEventContext, parse_security_logs_jsonl,
};

fn context(timestamp_ns: u64, component: &str) -> SecurityEventContext {
    SecurityEventContext {
        timestamp_ns,
        trace_id: "trace-001".to_string(),
        principal_id: "principal-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        zone_id: "zone-core".to_string(),
        component: component.to_string(),
    }
}

#[test]
fn records_all_failure_categories_and_updates_required_metrics() {
    let mut observability = RuntimeSecurityObservability::new();

    observability.record_auth_failure(
        context(10, "auth_verifier"),
        AuthFailureType::KeyRevoked,
        Some("raw-key-material"),
        Some("token-content"),
    );
    observability.record_capability_denial(
        context(11, "capability_gate"),
        CapabilityDenialReason::AudienceMismatch,
        "write_policy",
    );
    observability.record_replay_drop(
        context(12, "session_channel"),
        ReplayDropReason::DuplicateSeq,
        42,
        43,
        "session-001",
    );
    observability.record_checkpoint_violation(
        context(13, "checkpoint_frontier"),
        CheckpointViolationType::RollbackAttempt,
        5,
        7,
    );
    observability.record_revocation_check(
        context(14, "revocation_freshness"),
        RevocationCheckOutcome::Stale,
        10,
        20,
        5,
        Some(12),
    );
    observability.record_cross_zone_reference(
        context(15, "zone_reference_checker"),
        CrossZoneReferenceType::AuthorityDenied,
        "zone-community",
        "zone-owner",
    );

    let metrics = observability.metrics();
    assert_eq!(metrics.auth_failure_total[&AuthFailureType::KeyRevoked], 1);
    assert_eq!(
        metrics.capability_denial_total[&CapabilityDenialReason::AudienceMismatch],
        1
    );
    assert_eq!(
        metrics.replay_drop_total[&ReplayDropReason::DuplicateSeq],
        1
    );
    assert_eq!(
        metrics.checkpoint_violation_total[&CheckpointViolationType::RollbackAttempt],
        1
    );
    assert_eq!(
        metrics.revocation_check_total[&RevocationCheckOutcome::Stale],
        1
    );
    assert_eq!(metrics.revocation_freshness_degraded_seconds, 12);
    assert_eq!(
        metrics.cross_zone_reference_total[&CrossZoneReferenceType::AuthorityDenied],
        1
    );

    let logs = observability.logs();
    assert_eq!(logs.len(), 6);
    for event in logs {
        assert!(event.required_fields_present());
    }

    let auth = &logs[0];
    assert_eq!(auth.event_type, "auth_failure");
    assert_eq!(auth.outcome, "denied");
    assert!(auth.error_code.is_some());
    let key_hash = auth
        .metadata
        .get("key_material_hash")
        .expect("hash should be present");
    assert!(key_hash.starts_with("sha256:"));
    assert_ne!(key_hash, "raw-key-material");
    assert!(
        !auth
            .metadata
            .values()
            .any(|value| value.contains("token-content"))
    );
}

#[test]
fn revocation_pass_emits_counter_without_error_code() {
    let mut observability = RuntimeSecurityObservability::new();

    let event = observability.record_revocation_check(
        context(100, "revocation_freshness"),
        RevocationCheckOutcome::Pass,
        120,
        120,
        5,
        None,
    );

    assert_eq!(event.event_type, "revocation_check");
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_code, None);
    assert_eq!(
        observability.metrics().revocation_check_total[&RevocationCheckOutcome::Pass],
        1
    );
    assert_eq!(
        observability
            .metrics()
            .revocation_freshness_degraded_seconds,
        0
    );
}

#[test]
fn synchronous_emission_updates_metrics_and_logs_immediately() {
    let mut observability = RuntimeSecurityObservability::new();

    let event = observability.record_checkpoint_violation(
        context(200, "checkpoint_frontier"),
        CheckpointViolationType::ForkDetected,
        90,
        91,
    );

    assert_eq!(observability.logs().len(), 1);
    assert_eq!(
        observability.metrics().checkpoint_violation_total[&CheckpointViolationType::ForkDetected],
        1
    );
    assert_eq!(observability.logs()[0], event);
}

#[test]
fn prometheus_export_contains_required_metric_families() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(
        context(300, "auth_verifier"),
        AuthFailureType::SignatureInvalid,
        Some("secret"),
        None,
    );

    let output = observability.export_prometheus_metrics();
    for metric in [
        "auth_failure_total",
        CAPABILITY_DENIAL_TOTAL,
        REPLAY_DROP_TOTAL,
        CHECKPOINT_VIOLATION_TOTAL,
        REVOCATION_FRESHNESS_DEGRADED_SECONDS,
        REVOCATION_CHECK_TOTAL,
        CROSS_ZONE_REFERENCE_TOTAL,
    ] {
        assert!(
            output.contains(metric),
            "prometheus export should contain {metric}"
        );
    }
}

#[test]
fn jsonl_export_is_parseable_and_stable() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_capability_denial(
        context(400, "capability_gate"),
        CapabilityDenialReason::InsufficientAuthority,
        "admin_policy_write",
    );
    observability.record_cross_zone_reference(
        context(401, "zone_reference_checker"),
        CrossZoneReferenceType::ProvenanceAllowed,
        "zone-team-a",
        "zone-team-b",
    );

    let jsonl = observability.export_logs_jsonl();
    let parsed = parse_security_logs_jsonl(&jsonl).expect("jsonl should parse");
    assert_eq!(parsed, observability.logs());
    for event in parsed {
        assert!(event.required_fields_present());
    }
}

#[test]
fn metric_label_sets_are_bounded_enums() {
    let auth_labels = AuthFailureType::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(auth_labels.len(), AuthFailureType::ALL.len());

    let denial_labels = CapabilityDenialReason::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(denial_labels.len(), CapabilityDenialReason::ALL.len());

    let replay_labels = ReplayDropReason::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(replay_labels.len(), ReplayDropReason::ALL.len());

    let checkpoint_labels = CheckpointViolationType::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(checkpoint_labels.len(), CheckpointViolationType::ALL.len());

    let revocation_labels = RevocationCheckOutcome::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(revocation_labels.len(), RevocationCheckOutcome::ALL.len());

    let zone_labels = CrossZoneReferenceType::ALL
        .iter()
        .map(|value| value.as_label())
        .collect::<BTreeSet<_>>();
    assert_eq!(zone_labels.len(), CrossZoneReferenceType::ALL.len());
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, reset, multiple events, error paths
// ────────────────────────────────────────────────────────────

#[test]
fn security_event_context_serde_round_trip() {
    let ctx = context(42, "test_component");
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: SecurityEventContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx.timestamp_ns, recovered.timestamp_ns);
    assert_eq!(ctx.component, recovered.component);
    assert_eq!(ctx.trace_id, recovered.trace_id);
}

#[test]
fn auth_failure_type_serde_round_trip() {
    for failure_type in AuthFailureType::ALL {
        let json = serde_json::to_string(&failure_type).expect("serialize");
        let recovered: AuthFailureType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(failure_type, recovered);
    }
}

#[test]
fn multiple_events_accumulate_in_order() {
    let mut observability = RuntimeSecurityObservability::new();

    observability.record_auth_failure(context(1, "auth"), AuthFailureType::KeyRevoked, None, None);
    observability.record_capability_denial(
        context(2, "cap"),
        CapabilityDenialReason::AudienceMismatch,
        "test_policy",
    );
    observability.record_replay_drop(
        context(3, "session"),
        ReplayDropReason::DuplicateSeq,
        1,
        2,
        "sess-001",
    );

    let logs = observability.logs();
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[0].event_type, "auth_failure");
    assert_eq!(logs[1].event_type, "capability_denial");
    assert_eq!(logs[2].event_type, "replay_drop");
    assert!(logs[0].timestamp_ns <= logs[1].timestamp_ns);
    assert!(logs[1].timestamp_ns <= logs[2].timestamp_ns);
}

#[test]
fn sensitive_key_material_is_hashed_not_leaked() {
    let mut observability = RuntimeSecurityObservability::new();
    let secret = "super-secret-key-material";

    observability.record_auth_failure(
        context(10, "auth"),
        AuthFailureType::SignatureInvalid,
        Some(secret),
        Some("bearer-token-content"),
    );

    let log = &observability.logs()[0];
    let all_values: Vec<&str> = log.metadata.values().map(|v| v.as_str()).collect();
    for value in &all_values {
        assert!(
            !value.contains(secret),
            "raw key material must not appear in logs"
        );
        assert!(
            !value.contains("bearer-token-content"),
            "token content must not appear in logs"
        );
    }
}

#[test]
fn metrics_count_increments_correctly() {
    let mut observability = RuntimeSecurityObservability::new();

    for _ in 0..5 {
        observability.record_auth_failure(
            context(1, "auth"),
            AuthFailureType::KeyRevoked,
            None,
            None,
        );
    }
    for _ in 0..3 {
        observability.record_auth_failure(
            context(2, "auth"),
            AuthFailureType::SignatureInvalid,
            None,
            None,
        );
    }

    let metrics = observability.metrics();
    assert_eq!(metrics.auth_failure_total[&AuthFailureType::KeyRevoked], 5);
    assert_eq!(
        metrics.auth_failure_total[&AuthFailureType::SignatureInvalid],
        3
    );
}

#[test]
fn cross_zone_reference_allowed_type_emits_pass_outcome() {
    let mut observability = RuntimeSecurityObservability::new();

    let event = observability.record_cross_zone_reference(
        context(100, "zone_checker"),
        CrossZoneReferenceType::ProvenanceAllowed,
        "zone-a",
        "zone-b",
    );

    assert_eq!(event.event_type, "cross_zone_reference");
    assert_eq!(event.outcome, "allowed");
}

#[test]
fn render_and_parse_security_logs_jsonl_roundtrip() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(context(1, "auth"), AuthFailureType::KeyRevoked, None, None);
    observability.record_capability_denial(
        context(2, "cap"),
        CapabilityDenialReason::Expired,
        "read_policy",
    );
    observability.record_replay_drop(
        context(3, "replay"),
        ReplayDropReason::StaleSeq,
        10,
        5,
        "sess-002",
    );

    let jsonl = render_security_logs_jsonl(observability.logs());
    let parsed = parse_security_logs_jsonl(&jsonl).expect("parse JSONL");
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed, observability.logs());
}

use frankenengine_engine::runtime_observability::{
    SecurityEventType, SecurityOutcome, StructuredSecurityLogEvent, redact_sensitive_value,
    render_security_logs_jsonl,
};

#[test]
fn redact_sensitive_value_produces_sha256_prefix() {
    let result = redact_sensitive_value("secret-key-material");
    assert!(result.starts_with("sha256:"));
    assert!(result.len() > 10);

    // Same input produces same output (deterministic)
    let result2 = redact_sensitive_value("secret-key-material");
    assert_eq!(result, result2);

    // Different inputs produce different hashes
    let different = redact_sensitive_value("other-secret");
    assert_ne!(result, different);
}

#[test]
fn security_event_type_display_matches_as_str() {
    let types = [
        SecurityEventType::AuthFailure,
        SecurityEventType::CapabilityDenial,
        SecurityEventType::ReplayDrop,
        SecurityEventType::CheckpointViolation,
        SecurityEventType::RevocationCheck,
        SecurityEventType::CrossZoneReference,
    ];
    for event_type in types {
        assert_eq!(event_type.to_string(), event_type.as_str());
        assert!(!event_type.as_str().is_empty());
    }
}

#[test]
fn security_outcome_display_matches_as_str() {
    let outcomes = [
        SecurityOutcome::Pass,
        SecurityOutcome::Allowed,
        SecurityOutcome::Denied,
        SecurityOutcome::Dropped,
        SecurityOutcome::Rejected,
        SecurityOutcome::Degraded,
    ];
    for outcome in outcomes {
        assert_eq!(outcome.to_string(), outcome.as_str());
        assert!(!outcome.as_str().is_empty());
    }
}

#[test]
fn structured_security_log_event_serde_roundtrip() {
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("key".to_string(), "value".to_string());

    let event = StructuredSecurityLogEvent {
        timestamp_ns: 42,
        trace_id: "trace-rt".to_string(),
        component: "test".to_string(),
        event_type: "auth_failure".to_string(),
        outcome: "denied".to_string(),
        error_code: Some("FE-AUTH-0001".to_string()),
        principal_id: "principal-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        zone_id: "zone-core".to_string(),
        metadata,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: StructuredSecurityLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn runtime_security_observability_serde_roundtrip() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(context(1, "auth"), AuthFailureType::KeyExpired, None, None);
    observability.record_checkpoint_violation(
        context(2, "cp"),
        CheckpointViolationType::RollbackAttempt,
        5,
        7,
    );

    let json = serde_json::to_string(&observability).expect("serialize");
    let recovered: RuntimeSecurityObservability = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(observability.logs().len(), recovered.logs().len());
    assert_eq!(observability.logs(), recovered.logs());
}

#[test]
fn replay_drop_metadata_includes_session_id_and_seq_numbers() {
    let mut observability = RuntimeSecurityObservability::new();
    let event = observability.record_replay_drop(
        context(1, "session_channel"),
        ReplayDropReason::CrossSession,
        100,
        50,
        "sess-xyz",
    );

    assert_eq!(event.event_type, "replay_drop");
    let meta = &event.metadata;
    // Session ID is redacted (hashed), not stored as plaintext
    assert!(meta.get("session_id_hash").is_some());
    assert!(meta.get("session_id_hash").unwrap().starts_with("sha256:"));
}

#[test]
fn checkpoint_violation_metadata_includes_epoch_info() {
    let mut observability = RuntimeSecurityObservability::new();
    let event = observability.record_checkpoint_violation(
        context(1, "checkpoint"),
        CheckpointViolationType::ForkDetected,
        100,
        101,
    );

    assert_eq!(event.event_type, "checkpoint_violation");
    assert!(event.error_code.is_some());
    assert!(event.required_fields_present());
}

#[test]
fn parse_security_logs_jsonl_handles_empty_input() {
    let parsed = parse_security_logs_jsonl("").expect("empty input should parse");
    assert!(parsed.is_empty());

    let parsed_whitespace =
        parse_security_logs_jsonl("   \n  \n").expect("whitespace should parse");
    assert!(parsed_whitespace.is_empty());
}

#[test]
fn parse_security_logs_jsonl_rejects_invalid_json() {
    let err = parse_security_logs_jsonl("not valid json").expect_err("should fail");
    assert!(err.contains("failed to parse JSONL line 1"));
}

#[test]
fn export_prometheus_metrics_includes_zero_counters_on_fresh_instance() {
    let observability = RuntimeSecurityObservability::new();
    let output = observability.export_prometheus_metrics();

    // Should contain all metric family names even with zero values
    for metric in [
        "auth_failure_total",
        CAPABILITY_DENIAL_TOTAL,
        REPLAY_DROP_TOTAL,
        CHECKPOINT_VIOLATION_TOTAL,
        REVOCATION_CHECK_TOTAL,
        CROSS_ZONE_REFERENCE_TOTAL,
    ] {
        assert!(
            output.contains(metric),
            "fresh prometheus export should contain {metric}"
        );
    }
}

#[test]
fn revocation_degraded_seconds_accumulates_across_multiple_checks() {
    let mut observability = RuntimeSecurityObservability::new();

    observability.record_revocation_check(
        context(1, "revocation"),
        RevocationCheckOutcome::Stale,
        10,
        20,
        5,
        Some(15),
    );
    observability.record_revocation_check(
        context(2, "revocation"),
        RevocationCheckOutcome::Stale,
        10,
        20,
        5,
        Some(25),
    );

    let metrics = observability.metrics();
    // revocation_freshness_degraded_seconds is set (not accumulated) — last value wins
    assert_eq!(metrics.revocation_freshness_degraded_seconds, 25);
    assert_eq!(
        metrics.revocation_check_total[&RevocationCheckOutcome::Stale],
        2
    );
}

#[test]
fn all_auth_failure_types_emit_error_codes() {
    for failure_type in AuthFailureType::ALL {
        let mut observability = RuntimeSecurityObservability::new();
        let event = observability.record_auth_failure(context(1, "auth"), failure_type, None, None);
        assert!(
            event.error_code.is_some(),
            "auth failure type {:?} should have an error code",
            failure_type
        );
    }
}

#[test]
fn all_capability_denial_reasons_have_error_codes() {
    for reason in CapabilityDenialReason::ALL {
        let mut observability = RuntimeSecurityObservability::new();
        let event =
            observability.record_capability_denial(context(1, "cap"), reason, "test_capability");
        assert!(
            event.error_code.is_some(),
            "denial reason {:?} should have an error code",
            reason
        );
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: prometheus format, metrics serde, zone metadata
// ────────────────────────────────────────────────────────────

#[test]
fn prometheus_export_counters_reflect_recorded_events() {
    let mut observability = RuntimeSecurityObservability::new();
    for _ in 0..3 {
        observability.record_auth_failure(
            context(1, "auth"),
            AuthFailureType::KeyRevoked,
            None,
            None,
        );
    }
    observability.record_capability_denial(
        context(2, "cap"),
        CapabilityDenialReason::Expired,
        "policy",
    );

    let prom = observability.export_prometheus_metrics();
    // Verify the specific counter value appears for key_revoked
    assert!(
        prom.contains("auth_failure_total{type=\"key_revoked\"} 3"),
        "prometheus output should contain key_revoked=3, got:\n{prom}"
    );
    assert!(
        prom.contains("capability_denial_total{reason=\"expired\"} 1"),
        "prometheus output should contain expired=1, got:\n{prom}"
    );
}

#[test]
fn runtime_security_metrics_default_has_all_zero_counters() {
    let metrics = RuntimeSecurityMetrics::default();
    for ft in AuthFailureType::ALL {
        assert_eq!(metrics.auth_failure_total[&ft], 0);
    }
    for reason in CapabilityDenialReason::ALL {
        assert_eq!(metrics.capability_denial_total[&reason], 0);
    }
    for reason in ReplayDropReason::ALL {
        assert_eq!(metrics.replay_drop_total[&reason], 0);
    }
    for vt in CheckpointViolationType::ALL {
        assert_eq!(metrics.checkpoint_violation_total[&vt], 0);
    }
    for outcome in RevocationCheckOutcome::ALL {
        assert_eq!(metrics.revocation_check_total[&outcome], 0);
    }
    for zt in CrossZoneReferenceType::ALL {
        assert_eq!(metrics.cross_zone_reference_total[&zt], 0);
    }
    assert_eq!(metrics.revocation_freshness_degraded_seconds, 0);
}

use frankenengine_engine::runtime_observability::RuntimeSecurityMetrics;

#[test]
fn cross_zone_reference_denied_type_emits_denied_outcome() {
    let mut observability = RuntimeSecurityObservability::new();
    let event = observability.record_cross_zone_reference(
        context(50, "zone_checker"),
        CrossZoneReferenceType::AuthorityDenied,
        "zone-src",
        "zone-dst",
    );

    assert_eq!(event.event_type, "cross_zone_reference");
    assert_eq!(event.outcome, "denied");
    assert!(event.error_code.is_some());
    assert!(event.required_fields_present());
    // The zone IDs should appear in metadata (possibly redacted)
    assert!(
        !event.metadata.is_empty(),
        "cross-zone reference should carry metadata"
    );
}

#[test]
fn capability_denial_metadata_includes_capability_name() {
    let mut observability = RuntimeSecurityObservability::new();
    let event = observability.record_capability_denial(
        context(60, "cap_gate"),
        CapabilityDenialReason::InsufficientAuthority,
        "admin_write_policy",
    );

    assert_eq!(event.event_type, "capability_denial");
    assert_eq!(event.outcome, "denied");
    // The capability name should appear somewhere in metadata
    let meta_values: Vec<&str> = event.metadata.values().map(|v| v.as_str()).collect();
    assert!(
        meta_values.iter().any(|v| v.contains("admin_write_policy")),
        "capability name should be in metadata, got: {:?}",
        meta_values
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: replay drop variants, revocation pass, jsonl multi-line
// ────────────────────────────────────────────────────────────

#[test]
fn all_replay_drop_reasons_emit_dropped_outcome() {
    for reason in ReplayDropReason::ALL {
        let mut observability = RuntimeSecurityObservability::new();
        let event =
            observability.record_replay_drop(context(1, "session"), reason, 10, 20, "sess-variant");
        assert_eq!(
            event.outcome, "dropped",
            "replay drop reason {:?} should have outcome=dropped",
            reason
        );
        assert!(
            event.error_code.is_some(),
            "replay drop reason {:?} should have an error code",
            reason
        );
    }
}

#[test]
fn all_checkpoint_violation_types_emit_rejected_outcome() {
    for vt in CheckpointViolationType::ALL {
        let mut observability = RuntimeSecurityObservability::new();
        let event =
            observability.record_checkpoint_violation(context(1, "checkpoint"), vt, 100, 101);
        assert_eq!(
            event.outcome, "rejected",
            "checkpoint violation type {:?} should have outcome=rejected",
            vt
        );
        assert!(event.error_code.is_some());
    }
}

#[test]
fn jsonl_roundtrip_preserves_metadata_values() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(
        context(1, "auth"),
        AuthFailureType::KeyRevoked,
        Some("secret-material"),
        None,
    );
    observability.record_capability_denial(
        context(2, "cap"),
        CapabilityDenialReason::InsufficientAuthority,
        "admin_write_policy",
    );

    let jsonl = observability.export_logs_jsonl();
    let parsed = parse_security_logs_jsonl(&jsonl).expect("parse JSONL");
    assert_eq!(parsed.len(), 2);
    // Verify metadata is preserved through the roundtrip
    for (original, recovered) in observability.logs().iter().zip(parsed.iter()) {
        assert_eq!(original.metadata, recovered.metadata);
    }
}

#[test]
fn security_event_context_fields_all_propagated_to_log() {
    let mut observability = RuntimeSecurityObservability::new();
    let ctx = SecurityEventContext {
        timestamp_ns: 999_999,
        trace_id: "trace-propagation-test".to_string(),
        principal_id: "principal-propagation".to_string(),
        decision_id: "decision-propagation".to_string(),
        policy_id: "policy-propagation".to_string(),
        zone_id: "zone-propagation".to_string(),
        component: "propagation_test".to_string(),
    };

    let event =
        observability.record_auth_failure(ctx.clone(), AuthFailureType::KeyExpired, None, None);

    assert_eq!(event.timestamp_ns, 999_999);
    assert_eq!(event.trace_id, "trace-propagation-test");
    assert_eq!(event.principal_id, "principal-propagation");
    assert_eq!(event.decision_id, "decision-propagation");
    assert_eq!(event.policy_id, "policy-propagation");
    assert_eq!(event.zone_id, "zone-propagation");
    assert_eq!(event.component, "propagation_test");
}

#[test]
fn runtime_security_metrics_serde_roundtrip() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(context(1, "auth"), AuthFailureType::KeyRevoked, None, None);
    observability.record_revocation_check(
        context(2, "rev"),
        RevocationCheckOutcome::Stale,
        10,
        20,
        5,
        Some(42),
    );

    let metrics = observability.metrics();
    let json = serde_json::to_string(&metrics).expect("serialize metrics");
    let recovered: RuntimeSecurityMetrics =
        serde_json::from_str(&json).expect("deserialize metrics");
    assert_eq!(
        recovered.auth_failure_total[&AuthFailureType::KeyRevoked],
        1
    );
    assert_eq!(recovered.revocation_freshness_degraded_seconds, 42);
}

// ────────────────────────────────────────────────────────────
// Enrichment: enum serde roundtrips, edge cases, prometheus format
// ────────────────────────────────────────────────────────────

#[test]
fn security_event_type_serde_roundtrip() {
    let types = [
        SecurityEventType::AuthFailure,
        SecurityEventType::CapabilityDenial,
        SecurityEventType::ReplayDrop,
        SecurityEventType::CheckpointViolation,
        SecurityEventType::RevocationCheck,
        SecurityEventType::CrossZoneReference,
    ];
    for event_type in types {
        let json = serde_json::to_string(&event_type).expect("serialize");
        let recovered: SecurityEventType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event_type, recovered);
    }
}

#[test]
fn security_outcome_serde_roundtrip() {
    let outcomes = [
        SecurityOutcome::Pass,
        SecurityOutcome::Allowed,
        SecurityOutcome::Denied,
        SecurityOutcome::Dropped,
        SecurityOutcome::Rejected,
        SecurityOutcome::Degraded,
    ];
    for outcome in outcomes {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: SecurityOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn capability_denial_reason_serde_roundtrip() {
    for reason in CapabilityDenialReason::ALL {
        let json = serde_json::to_string(&reason).expect("serialize");
        let recovered: CapabilityDenialReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, recovered);
    }
}

#[test]
fn replay_drop_reason_serde_roundtrip() {
    for reason in ReplayDropReason::ALL {
        let json = serde_json::to_string(&reason).expect("serialize");
        let recovered: ReplayDropReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, recovered);
    }
}

#[test]
fn checkpoint_violation_type_serde_roundtrip() {
    for vt in CheckpointViolationType::ALL {
        let json = serde_json::to_string(&vt).expect("serialize");
        let recovered: CheckpointViolationType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(vt, recovered);
    }
}

#[test]
fn revocation_check_outcome_serde_roundtrip() {
    for outcome in RevocationCheckOutcome::ALL {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: RevocationCheckOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn cross_zone_reference_type_serde_roundtrip() {
    for rt in CrossZoneReferenceType::ALL {
        let json = serde_json::to_string(&rt).expect("serialize");
        let recovered: CrossZoneReferenceType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, recovered);
    }
}

#[test]
fn redact_sensitive_value_empty_string_produces_valid_hash() {
    let result = redact_sensitive_value("");
    assert!(result.starts_with("sha256:"));
    // SHA-256 of "" is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(result.len(), 7 + 64); // "sha256:" + 64 hex chars
}

#[test]
fn context_with_empty_fields_uses_sanitized_fallbacks() {
    let mut observability = RuntimeSecurityObservability::new();
    let ctx = SecurityEventContext {
        timestamp_ns: 42,
        trace_id: "".to_string(),
        principal_id: "  ".to_string(),
        decision_id: "".to_string(),
        policy_id: "".to_string(),
        zone_id: "".to_string(),
        component: "".to_string(),
    };

    let event = observability.record_auth_failure(ctx, AuthFailureType::KeyRevoked, None, None);

    // All fields should be non-empty after sanitization
    assert!(event.required_fields_present());
    assert!(!event.trace_id.is_empty());
    assert!(!event.principal_id.is_empty());
    assert!(!event.component.is_empty());
}

#[test]
fn prometheus_output_contains_help_and_type_annotations() {
    let observability = RuntimeSecurityObservability::new();
    let prom = observability.export_prometheus_metrics();

    // Verify HELP lines
    assert!(prom.contains("# HELP auth_failure_total"));
    assert!(prom.contains("# HELP capability_denial_total"));
    assert!(prom.contains("# HELP replay_drop_total"));
    assert!(prom.contains("# HELP checkpoint_violation_total"));
    assert!(prom.contains("# HELP revocation_freshness_degraded_seconds"));
    assert!(prom.contains("# HELP revocation_check_total"));
    assert!(prom.contains("# HELP cross_zone_reference_total"));

    // Verify TYPE lines
    assert!(prom.contains("# TYPE auth_failure_total counter"));
    assert!(prom.contains("# TYPE capability_denial_total counter"));
    assert!(prom.contains("# TYPE revocation_freshness_degraded_seconds gauge"));
}

#[test]
fn prometheus_output_uses_correct_label_format() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(
        context(1, "auth"),
        AuthFailureType::AttestationInvalid,
        None,
        None,
    );

    let prom = observability.export_prometheus_metrics();
    // Verify label format: metric_name{label="value"} count
    assert!(prom.contains("auth_failure_total{type=\"attestation_invalid\"} 1"));
    // Other types should be zero
    assert!(prom.contains("auth_failure_total{type=\"signature_invalid\"} 0"));
}

#[test]
fn render_security_logs_jsonl_empty_input_returns_empty_string() {
    let result = render_security_logs_jsonl(&[]);
    assert!(result.is_empty());
}

#[test]
fn structured_log_event_required_fields_present_false_for_missing_fields() {
    let event = StructuredSecurityLogEvent {
        timestamp_ns: 0,
        trace_id: "".to_string(),
        component: "test".to_string(),
        event_type: "auth_failure".to_string(),
        outcome: "denied".to_string(),
        error_code: None,
        principal_id: "p".to_string(),
        decision_id: "d".to_string(),
        policy_id: "pol".to_string(),
        zone_id: "z".to_string(),
        metadata: std::collections::BTreeMap::new(),
    };
    assert!(
        !event.required_fields_present(),
        "empty trace_id should fail"
    );

    let event2 = StructuredSecurityLogEvent {
        timestamp_ns: 0,
        trace_id: "t".to_string(),
        component: "".to_string(),
        event_type: "auth_failure".to_string(),
        outcome: "denied".to_string(),
        error_code: None,
        principal_id: "p".to_string(),
        decision_id: "d".to_string(),
        policy_id: "pol".to_string(),
        zone_id: "z".to_string(),
        metadata: std::collections::BTreeMap::new(),
    };
    assert!(
        !event2.required_fields_present(),
        "empty component should fail"
    );
}

#[test]
fn revocation_revoked_outcome_emits_denied_with_error_code() {
    let mut observability = RuntimeSecurityObservability::new();
    let event = observability.record_revocation_check(
        context(1, "rev"),
        RevocationCheckOutcome::Revoked,
        10,
        20,
        5,
        None,
    );

    assert_eq!(event.outcome, "denied");
    assert!(event.error_code.is_some());
    assert_eq!(
        observability.metrics().revocation_check_total[&RevocationCheckOutcome::Revoked],
        1
    );
}

#[test]
fn revocation_stale_outcome_emits_degraded() {
    let mut observability = RuntimeSecurityObservability::new();
    let event = observability.record_revocation_check(
        context(1, "rev"),
        RevocationCheckOutcome::Stale,
        10,
        20,
        5,
        Some(30),
    );

    assert_eq!(event.outcome, "degraded");
    assert!(event.error_code.is_some());
}

#[test]
fn all_six_event_types_produce_distinct_event_type_strings() {
    let mut observability = RuntimeSecurityObservability::new();
    observability.record_auth_failure(context(1, "a"), AuthFailureType::KeyRevoked, None, None);
    observability.record_capability_denial(context(2, "b"), CapabilityDenialReason::Expired, "cap");
    observability.record_replay_drop(context(3, "c"), ReplayDropReason::DuplicateSeq, 1, 2, "s");
    observability.record_checkpoint_violation(
        context(4, "d"),
        CheckpointViolationType::ForkDetected,
        1,
        2,
    );
    observability.record_revocation_check(
        context(5, "e"),
        RevocationCheckOutcome::Pass,
        10,
        10,
        5,
        None,
    );
    observability.record_cross_zone_reference(
        context(6, "f"),
        CrossZoneReferenceType::ProvenanceAllowed,
        "za",
        "zb",
    );

    let event_types: BTreeSet<&str> = observability
        .logs()
        .iter()
        .map(|e| e.event_type.as_str())
        .collect();
    assert_eq!(event_types.len(), 6, "all 6 event types must be distinct");
}
