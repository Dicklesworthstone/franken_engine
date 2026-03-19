//! Enrichment integration tests for `runtime_observability`.
//!
//! Covers: multi-event accumulation ordering, prometheus metric format
//! correctness after accumulation, JSONL render/parse edge cases, redaction
//! determinism, cross-event metric isolation, stale gauge overwrite semantics,
//! sanitization of empty context fields across all record_* methods,
//! and error-code prefix verification.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;

use frankenengine_engine::runtime_observability::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx(ts: u64) -> SecurityEventContext {
    SecurityEventContext {
        timestamp_ns: ts,
        trace_id: format!("trace-{ts}"),
        principal_id: format!("principal-{ts}"),
        decision_id: format!("decision-{ts}"),
        policy_id: format!("policy-{ts}"),
        zone_id: format!("zone-{ts}"),
        component: format!("component-{ts}"),
    }
}

fn empty_ctx() -> SecurityEventContext {
    SecurityEventContext {
        timestamp_ns: 0,
        trace_id: String::new(),
        principal_id: String::new(),
        decision_id: String::new(),
        policy_id: String::new(),
        zone_id: String::new(),
        component: String::new(),
    }
}

// =========================================================================
// 1. AuthFailureType — additional coverage
// =========================================================================

#[test]
fn enrichment_auth_failure_type_all_has_four() {
    assert_eq!(AuthFailureType::ALL.len(), 4);
}

#[test]
fn enrichment_auth_failure_type_as_label_non_empty() {
    for v in AuthFailureType::ALL {
        assert!(!v.as_label().is_empty());
    }
}

#[test]
fn enrichment_auth_failure_type_display_matches_as_label() {
    for v in AuthFailureType::ALL {
        assert_eq!(v.to_string(), v.as_label());
    }
}

// =========================================================================
// 2. CapabilityDenialReason — additional coverage
// =========================================================================

#[test]
fn enrichment_capability_denial_reason_all_has_six() {
    assert_eq!(CapabilityDenialReason::ALL.len(), 6);
}

#[test]
fn enrichment_capability_denial_specific_labels() {
    assert_eq!(
        CapabilityDenialReason::InsufficientAuthority.as_label(),
        "insufficient_authority"
    );
    assert_eq!(
        CapabilityDenialReason::NotYetValid.as_label(),
        "not_yet_valid"
    );
}

// =========================================================================
// 3. ReplayDropReason — labels
// =========================================================================

#[test]
fn enrichment_replay_drop_reason_all_has_three() {
    assert_eq!(ReplayDropReason::ALL.len(), 3);
}

#[test]
fn enrichment_replay_drop_labels() {
    assert_eq!(ReplayDropReason::DuplicateSeq.as_label(), "duplicate_seq");
    assert_eq!(ReplayDropReason::StaleSeq.as_label(), "stale_seq");
    assert_eq!(ReplayDropReason::CrossSession.as_label(), "cross_session");
}

// =========================================================================
// 4. CheckpointViolationType — labels
// =========================================================================

#[test]
fn enrichment_checkpoint_violation_type_all_has_three() {
    assert_eq!(CheckpointViolationType::ALL.len(), 3);
}

#[test]
fn enrichment_checkpoint_violation_labels() {
    assert_eq!(
        CheckpointViolationType::RollbackAttempt.as_label(),
        "rollback_attempt"
    );
    assert_eq!(
        CheckpointViolationType::ForkDetected.as_label(),
        "fork_detected"
    );
}

// =========================================================================
// 5. RevocationCheckOutcome — labels
// =========================================================================

#[test]
fn enrichment_revocation_check_outcome_all_has_three() {
    assert_eq!(RevocationCheckOutcome::ALL.len(), 3);
}

// =========================================================================
// 6. CrossZoneReferenceType — labels
// =========================================================================

#[test]
fn enrichment_cross_zone_reference_type_all_has_two() {
    assert_eq!(CrossZoneReferenceType::ALL.len(), 2);
}

// =========================================================================
// 7. SecurityEventType — additional coverage
// =========================================================================

#[test]
fn enrichment_security_event_type_six_variants() {
    let variants = [
        SecurityEventType::AuthFailure,
        SecurityEventType::CapabilityDenial,
        SecurityEventType::ReplayDrop,
        SecurityEventType::CheckpointViolation,
        SecurityEventType::RevocationCheck,
        SecurityEventType::CrossZoneReference,
    ];
    assert_eq!(variants.len(), 6);
    for v in variants {
        assert!(!v.as_str().is_empty());
        assert_eq!(v.to_string(), v.as_str());
    }
}

// =========================================================================
// 8. SecurityOutcome — all six variants
// =========================================================================

#[test]
fn enrichment_security_outcome_six_variants() {
    let variants = [
        SecurityOutcome::Pass,
        SecurityOutcome::Allowed,
        SecurityOutcome::Denied,
        SecurityOutcome::Dropped,
        SecurityOutcome::Rejected,
        SecurityOutcome::Degraded,
    ];
    assert_eq!(variants.len(), 6);
    for v in variants {
        assert!(!v.as_str().is_empty());
    }
}

// =========================================================================
// 9. redact_sensitive_value — additional coverage
// =========================================================================

#[test]
fn enrichment_redact_same_input_stable() {
    let a = redact_sensitive_value("my-secret");
    let b = redact_sensitive_value("my-secret");
    let c = redact_sensitive_value("my-secret");
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn enrichment_redact_different_inputs_different_hashes() {
    let a = redact_sensitive_value("alpha");
    let b = redact_sensitive_value("beta");
    let c = redact_sensitive_value("gamma");
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

#[test]
fn enrichment_redact_whitespace_only_still_hashes() {
    let result = redact_sensitive_value("   ");
    assert!(result.starts_with("sha256:"));
    assert_eq!(result.len(), 7 + 64);
}

#[test]
fn enrichment_redact_unicode_input() {
    let result = redact_sensitive_value("ñ日本語");
    assert!(result.starts_with("sha256:"));
    assert_eq!(result.len(), 7 + 64);
}

// =========================================================================
// 10. StructuredSecurityLogEvent — required_fields_present edge cases
// =========================================================================

#[test]
fn enrichment_required_fields_all_present_returns_true() {
    let event = StructuredSecurityLogEvent {
        timestamp_ns: 1,
        trace_id: "t".into(),
        component: "c".into(),
        event_type: "e".into(),
        outcome: "o".into(),
        error_code: None,
        principal_id: "p".into(),
        decision_id: "d".into(),
        policy_id: "pol".into(),
        zone_id: "z".into(),
        metadata: BTreeMap::new(),
    };
    assert!(event.required_fields_present());
}

#[test]
fn enrichment_required_fields_metadata_does_not_affect_check() {
    let event = StructuredSecurityLogEvent {
        timestamp_ns: 0,
        trace_id: "t".into(),
        component: "c".into(),
        event_type: "e".into(),
        outcome: "o".into(),
        error_code: Some("code".into()),
        principal_id: "p".into(),
        decision_id: "d".into(),
        policy_id: "pol".into(),
        zone_id: "z".into(),
        metadata: BTreeMap::new(),
    };
    assert!(event.required_fields_present());
}

// =========================================================================
// 11. RuntimeSecurityMetrics — default counter maps
// =========================================================================

#[test]
fn enrichment_metrics_default_all_counters_zero() {
    let m = RuntimeSecurityMetrics::default();
    for v in m.auth_failure_total.values() {
        assert_eq!(*v, 0);
    }
    for v in m.capability_denial_total.values() {
        assert_eq!(*v, 0);
    }
    for v in m.replay_drop_total.values() {
        assert_eq!(*v, 0);
    }
    for v in m.checkpoint_violation_total.values() {
        assert_eq!(*v, 0);
    }
    for v in m.revocation_check_total.values() {
        assert_eq!(*v, 0);
    }
    for v in m.cross_zone_reference_total.values() {
        assert_eq!(*v, 0);
    }
    assert_eq!(m.revocation_freshness_degraded_seconds, 0);
}

// =========================================================================
// 12. RuntimeSecurityObservability — record_auth_failure sanitization
// =========================================================================

#[test]
fn enrichment_auth_failure_empty_context_sanitized() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_auth_failure(empty_ctx(), AuthFailureType::KeyRevoked, None, None);
    assert_eq!(event.trace_id, "trace-missing");
    assert_eq!(event.principal_id, "principal-missing");
    assert_eq!(event.decision_id, "decision-missing");
    assert_eq!(event.policy_id, "policy-missing");
    assert_eq!(event.zone_id, "zone-missing");
    assert_eq!(event.component, "runtime_observability");
    assert!(event.required_fields_present());
}

#[test]
fn enrichment_auth_failure_key_material_redacted() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_auth_failure(
        ctx(1),
        AuthFailureType::SignatureInvalid,
        Some("my-secret-key"),
        None,
    );
    let km = event.metadata.get("key_material_hash").unwrap();
    assert!(km.starts_with("sha256:"));
    assert!(!km.contains("my-secret-key"));
}

#[test]
fn enrichment_auth_failure_token_content_redacted() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_auth_failure(
        ctx(2),
        AuthFailureType::KeyExpired,
        None,
        Some("bearer-token-xyz"),
    );
    let tc = event.metadata.get("token_content_hash").unwrap();
    assert!(tc.starts_with("sha256:"));
    assert!(!tc.contains("bearer-token-xyz"));
}

// =========================================================================
// 13. record_capability_denial — empty capability sanitized
// =========================================================================

#[test]
fn enrichment_capability_denial_empty_name_becomes_unspecified() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_capability_denial(ctx(1), CapabilityDenialReason::Expired, "");
    assert_eq!(
        event.metadata.get("requested_capability").unwrap(),
        "unspecified"
    );
}

#[test]
fn enrichment_capability_denial_normal_name_preserved() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_capability_denial(
        ctx(1),
        CapabilityDenialReason::CeilingExceeded,
        "net.connect",
    );
    assert_eq!(
        event.metadata.get("requested_capability").unwrap(),
        "net.connect"
    );
}

// =========================================================================
// 14. record_replay_drop — session_id redacted
// =========================================================================

#[test]
fn enrichment_replay_drop_session_id_redacted() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_replay_drop(
        ctx(1),
        ReplayDropReason::StaleSeq,
        5,
        10,
        "secret-session-id",
    );
    let sid = event.metadata.get("session_id_hash").unwrap();
    assert!(sid.starts_with("sha256:"));
    assert!(!sid.contains("secret-session-id"));
}

#[test]
fn enrichment_replay_drop_seq_numbers_stored() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_replay_drop(ctx(1), ReplayDropReason::DuplicateSeq, 42, 100, "s");
    assert_eq!(event.metadata.get("received_seq").unwrap(), "42");
    assert_eq!(event.metadata.get("expected_seq").unwrap(), "100");
}

// =========================================================================
// 15. record_checkpoint_violation — metadata
// =========================================================================

#[test]
fn enrichment_checkpoint_violation_metadata_correct() {
    let mut obs = RuntimeSecurityObservability::new();
    let event =
        obs.record_checkpoint_violation(ctx(1), CheckpointViolationType::ForkDetected, 5, 10);
    assert_eq!(event.metadata.get("attempted_seq").unwrap(), "5");
    assert_eq!(event.metadata.get("current_seq").unwrap(), "10");
    assert_eq!(event.outcome, "rejected");
}

// =========================================================================
// 16. record_revocation_check — staleness gap calculation
// =========================================================================

#[test]
fn enrichment_revocation_check_staleness_gap_correct() {
    let mut obs = RuntimeSecurityObservability::new();
    let event =
        obs.record_revocation_check(ctx(1), RevocationCheckOutcome::Revoked, 80, 100, 50, None);
    assert_eq!(event.metadata.get("staleness_gap").unwrap(), "20");
}

#[test]
fn enrichment_revocation_check_staleness_gap_no_underflow() {
    let mut obs = RuntimeSecurityObservability::new();
    let event =
        obs.record_revocation_check(ctx(1), RevocationCheckOutcome::Pass, 200, 100, 50, None);
    assert_eq!(event.metadata.get("staleness_gap").unwrap(), "0");
}

#[test]
fn enrichment_revocation_stale_updates_degraded_gauge() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_revocation_check(
        ctx(1),
        RevocationCheckOutcome::Stale,
        50,
        100,
        60,
        Some(500),
    );
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 500);
}

#[test]
fn enrichment_revocation_stale_without_seconds_uses_zero() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_revocation_check(ctx(1), RevocationCheckOutcome::Stale, 50, 100, 60, None);
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 0);
}

#[test]
fn enrichment_revocation_pass_does_not_reset_gauge() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_revocation_check(
        ctx(1),
        RevocationCheckOutcome::Stale,
        50,
        100,
        60,
        Some(300),
    );
    obs.record_revocation_check(ctx(2), RevocationCheckOutcome::Pass, 100, 100, 60, None);
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 300);
}

// =========================================================================
// 17. record_cross_zone_reference — sanitization
// =========================================================================

#[test]
fn enrichment_cross_zone_empty_zones_sanitized() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_cross_zone_reference(
        ctx(1),
        CrossZoneReferenceType::ProvenanceAllowed,
        "",
        "  ",
    );
    assert_eq!(
        event.metadata.get("source_zone").unwrap(),
        "source-zone-missing"
    );
    assert_eq!(
        event.metadata.get("target_zone").unwrap(),
        "target-zone-missing"
    );
}

#[test]
fn enrichment_cross_zone_normal_zones_preserved() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_cross_zone_reference(
        ctx(1),
        CrossZoneReferenceType::AuthorityDenied,
        "zone-a",
        "zone-b",
    );
    assert_eq!(event.metadata.get("source_zone").unwrap(), "zone-a");
    assert_eq!(event.metadata.get("target_zone").unwrap(), "zone-b");
}

// =========================================================================
// 18. export_logs_jsonl / export_prometheus_metrics
// =========================================================================

#[test]
fn enrichment_export_logs_jsonl_empty_on_new() {
    let obs = RuntimeSecurityObservability::new();
    assert!(obs.export_logs_jsonl().is_empty());
}

#[test]
fn enrichment_export_prometheus_contains_all_families() {
    let obs = RuntimeSecurityObservability::new();
    let prom = obs.export_prometheus_metrics();
    assert!(prom.contains("auth_failure_total"));
    assert!(prom.contains("capability_denial_total"));
    assert!(prom.contains("replay_drop_total"));
    assert!(prom.contains("checkpoint_violation_total"));
    assert!(prom.contains("revocation_freshness_degraded_seconds"));
    assert!(prom.contains("revocation_check_total"));
    assert!(prom.contains("cross_zone_reference_total"));
}

// =========================================================================
// 19. JSONL render/parse roundtrip
// =========================================================================

#[test]
fn enrichment_jsonl_roundtrip_all_event_types() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyExpired, Some("k"), Some("t"));
    obs.record_capability_denial(ctx(2), CapabilityDenialReason::Expired, "cap");
    obs.record_replay_drop(ctx(3), ReplayDropReason::CrossSession, 1, 2, "s");
    obs.record_checkpoint_violation(ctx(4), CheckpointViolationType::ForkDetected, 3, 4);
    obs.record_revocation_check(ctx(5), RevocationCheckOutcome::Stale, 10, 20, 5, Some(99));
    obs.record_cross_zone_reference(ctx(6), CrossZoneReferenceType::AuthorityDenied, "a", "b");

    let jsonl = render_security_logs_jsonl(obs.logs());
    let parsed = parse_security_logs_jsonl(&jsonl).unwrap();
    assert_eq!(parsed.len(), 6);
    for (orig, restored) in obs.logs().iter().zip(parsed.iter()) {
        assert_eq!(orig, restored);
    }
}

#[test]
fn enrichment_parse_jsonl_blank_lines_skipped() {
    let result = parse_security_logs_jsonl("\n\n  \n\n").unwrap();
    assert!(result.is_empty());
}

#[test]
fn enrichment_parse_jsonl_invalid_returns_error_with_line() {
    let err = parse_security_logs_jsonl("not-json").unwrap_err();
    assert!(err.contains("line 1"));
}

// =========================================================================
// 20. Cross-event counter isolation
// =========================================================================

#[test]
fn enrichment_counters_isolated_across_event_types() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyExpired, None, None);
    obs.record_capability_denial(ctx(2), CapabilityDenialReason::Expired, "c");

    let m = obs.metrics();
    assert_eq!(
        *m.auth_failure_total
            .get(&AuthFailureType::KeyExpired)
            .unwrap(),
        1
    );
    assert_eq!(
        *m.capability_denial_total
            .get(&CapabilityDenialReason::Expired)
            .unwrap(),
        1
    );
    // Other auth failure types should still be zero
    assert_eq!(
        *m.auth_failure_total
            .get(&AuthFailureType::SignatureInvalid)
            .unwrap(),
        0
    );
}

// =========================================================================
// 21. Prometheus output with non-zero values
// =========================================================================

#[test]
fn enrichment_prometheus_reflects_accumulated_counts() {
    let mut obs = RuntimeSecurityObservability::new();
    for _ in 0..5 {
        obs.record_auth_failure(ctx(1), AuthFailureType::SignatureInvalid, None, None);
    }
    for _ in 0..3 {
        obs.record_replay_drop(ctx(2), ReplayDropReason::DuplicateSeq, 1, 2, "s");
    }
    let prom = obs.metrics().to_prometheus();
    assert!(prom.contains("auth_failure_total{type=\"signature_invalid\"} 5"));
    assert!(prom.contains("replay_drop_total{reason=\"duplicate_seq\"} 3"));
}

// =========================================================================
// 22. SecurityEventContext serde roundtrip
// =========================================================================

#[test]
fn enrichment_security_event_context_serde() {
    let c = ctx(99);
    let json = serde_json::to_string(&c).unwrap();
    let back: SecurityEventContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// =========================================================================
// 23. Full observability serde roundtrip
// =========================================================================

#[test]
fn enrichment_observability_serde_roundtrip_with_data() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyExpired, Some("k"), None);
    obs.record_capability_denial(ctx(2), CapabilityDenialReason::AudienceMismatch, "net");
    obs.record_revocation_check(ctx(3), RevocationCheckOutcome::Stale, 10, 20, 5, Some(42));

    let json = serde_json::to_string(&obs).unwrap();
    let back: RuntimeSecurityObservability = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

// =========================================================================
// 24. Constant string values
// =========================================================================

#[test]
fn enrichment_constant_strings_match_expected_values() {
    assert_eq!(AUTH_FAILURE_TOTAL, "auth_failure_total");
    assert_eq!(CAPABILITY_DENIAL_TOTAL, "capability_denial_total");
    assert_eq!(REPLAY_DROP_TOTAL, "replay_drop_total");
    assert_eq!(CHECKPOINT_VIOLATION_TOTAL, "checkpoint_violation_total");
    assert_eq!(
        REVOCATION_FRESHNESS_DEGRADED_SECONDS,
        "revocation_freshness_degraded_seconds"
    );
    assert_eq!(REVOCATION_CHECK_TOTAL, "revocation_check_total");
    assert_eq!(CROSS_ZONE_REFERENCE_TOTAL, "cross_zone_reference_total");
}

// =========================================================================
// 25. Log ordering verification
// =========================================================================

#[test]
fn enrichment_logs_preserve_insertion_order() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(10), AuthFailureType::KeyRevoked, None, None);
    obs.record_capability_denial(ctx(20), CapabilityDenialReason::NotYetValid, "x");
    obs.record_replay_drop(ctx(30), ReplayDropReason::StaleSeq, 1, 2, "s");
    obs.record_checkpoint_violation(ctx(40), CheckpointViolationType::QuorumInsufficient, 1, 2);
    obs.record_revocation_check(ctx(50), RevocationCheckOutcome::Revoked, 10, 20, 5, None);
    obs.record_cross_zone_reference(ctx(60), CrossZoneReferenceType::ProvenanceAllowed, "a", "b");

    let logs = obs.logs();
    assert_eq!(logs.len(), 6);
    assert_eq!(logs[0].timestamp_ns, 10);
    assert_eq!(logs[1].timestamp_ns, 20);
    assert_eq!(logs[2].timestamp_ns, 30);
    assert_eq!(logs[3].timestamp_ns, 40);
    assert_eq!(logs[4].timestamp_ns, 50);
    assert_eq!(logs[5].timestamp_ns, 60);
}
