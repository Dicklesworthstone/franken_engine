#![forbid(unsafe_code)]

//! Comprehensive integration tests for the `runtime_observability` module.
//!
//! Covers all public enums (labels, Display, serde, ALL constants, Ord),
//! SecurityEventContext sanitization, StructuredSecurityLogEvent validation,
//! RuntimeSecurityMetrics (default, prometheus export, serde),
//! RuntimeSecurityObservability (record_* methods, metric accumulation, log
//! accumulation, export_prometheus_metrics, export_logs_jsonl),
//! JSONL render/parse round-trips, redaction, and cross-event interaction
//! scenarios.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::runtime_observability::{
    AUTH_FAILURE_TOTAL, AuthFailureType, CAPABILITY_DENIAL_TOTAL, CHECKPOINT_VIOLATION_TOTAL,
    CROSS_ZONE_REFERENCE_TOTAL, CapabilityDenialReason, CheckpointViolationType,
    CrossZoneReferenceType, REPLAY_DROP_TOTAL, REVOCATION_CHECK_TOTAL,
    REVOCATION_FRESHNESS_DEGRADED_SECONDS, ReplayDropReason, RevocationCheckOutcome,
    RuntimeSecurityMetrics, RuntimeSecurityObservability, SecurityEventContext, SecurityEventType,
    SecurityOutcome, StructuredSecurityLogEvent, parse_security_logs_jsonl, redact_sensitive_value,
    render_security_logs_jsonl,
};

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

// ============================================================================
// Section 1: Public constant strings
// ============================================================================

#[test]
fn public_metric_name_constants_are_non_empty_and_distinct() {
    let names = [
        AUTH_FAILURE_TOTAL,
        CAPABILITY_DENIAL_TOTAL,
        REPLAY_DROP_TOTAL,
        CHECKPOINT_VIOLATION_TOTAL,
        REVOCATION_FRESHNESS_DEGRADED_SECONDS,
        REVOCATION_CHECK_TOTAL,
        CROSS_ZONE_REFERENCE_TOTAL,
    ];
    let set: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(set.len(), names.len());
    for name in &names {
        assert!(!name.is_empty());
    }
}

// ============================================================================
// Section 2: Enum labels, Display, serde, ordering
// ============================================================================

#[test]
fn auth_failure_type_all_labels_and_display_match() {
    for variant in AuthFailureType::ALL {
        assert_eq!(variant.to_string(), variant.as_label());
    }
}

#[test]
fn auth_failure_type_serde_roundtrip_all_variants() {
    for variant in AuthFailureType::ALL {
        let json = serde_json::to_string(&variant).unwrap();
        let back: AuthFailureType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn auth_failure_type_ord_is_consistent() {
    let mut sorted = AuthFailureType::ALL.to_vec();
    sorted.sort();
    // Just verify it doesn't panic and we still have all variants.
    assert_eq!(sorted.len(), 4);
}

#[test]
fn capability_denial_reason_all_labels_and_display_match() {
    for variant in CapabilityDenialReason::ALL {
        assert_eq!(variant.to_string(), variant.as_label());
    }
}

#[test]
fn capability_denial_reason_serde_roundtrip_all_variants() {
    for variant in CapabilityDenialReason::ALL {
        let json = serde_json::to_string(&variant).unwrap();
        let back: CapabilityDenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn replay_drop_reason_all_labels_and_display_match() {
    for variant in ReplayDropReason::ALL {
        assert_eq!(variant.to_string(), variant.as_label());
    }
}

#[test]
fn replay_drop_reason_serde_roundtrip_all_variants() {
    for variant in ReplayDropReason::ALL {
        let json = serde_json::to_string(&variant).unwrap();
        let back: ReplayDropReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn checkpoint_violation_type_all_labels_and_display_match() {
    for variant in CheckpointViolationType::ALL {
        assert_eq!(variant.to_string(), variant.as_label());
    }
}

#[test]
fn checkpoint_violation_type_serde_roundtrip_all_variants() {
    for variant in CheckpointViolationType::ALL {
        let json = serde_json::to_string(&variant).unwrap();
        let back: CheckpointViolationType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn revocation_check_outcome_all_labels_and_display_match() {
    for variant in RevocationCheckOutcome::ALL {
        assert_eq!(variant.to_string(), variant.as_label());
    }
}

#[test]
fn revocation_check_outcome_serde_roundtrip_all_variants() {
    for variant in RevocationCheckOutcome::ALL {
        let json = serde_json::to_string(&variant).unwrap();
        let back: RevocationCheckOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn cross_zone_reference_type_all_labels_and_display_match() {
    for variant in CrossZoneReferenceType::ALL {
        assert_eq!(variant.to_string(), variant.as_label());
    }
}

#[test]
fn cross_zone_reference_type_serde_roundtrip_all_variants() {
    for variant in CrossZoneReferenceType::ALL {
        let json = serde_json::to_string(&variant).unwrap();
        let back: CrossZoneReferenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variant);
    }
}

#[test]
fn security_event_type_as_str_and_display_match() {
    let variants = [
        SecurityEventType::AuthFailure,
        SecurityEventType::CapabilityDenial,
        SecurityEventType::ReplayDrop,
        SecurityEventType::CheckpointViolation,
        SecurityEventType::RevocationCheck,
        SecurityEventType::CrossZoneReference,
    ];
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn security_event_type_serde_roundtrip_all_variants() {
    let variants = [
        SecurityEventType::AuthFailure,
        SecurityEventType::CapabilityDenial,
        SecurityEventType::ReplayDrop,
        SecurityEventType::CheckpointViolation,
        SecurityEventType::RevocationCheck,
        SecurityEventType::CrossZoneReference,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: SecurityEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn security_outcome_as_str_and_display_match() {
    let variants = [
        SecurityOutcome::Pass,
        SecurityOutcome::Allowed,
        SecurityOutcome::Denied,
        SecurityOutcome::Dropped,
        SecurityOutcome::Rejected,
        SecurityOutcome::Degraded,
    ];
    for v in variants {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn security_outcome_serde_roundtrip_all_variants() {
    let variants = [
        SecurityOutcome::Pass,
        SecurityOutcome::Allowed,
        SecurityOutcome::Denied,
        SecurityOutcome::Dropped,
        SecurityOutcome::Rejected,
        SecurityOutcome::Degraded,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: SecurityOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ============================================================================
// Section 3: StructuredSecurityLogEvent — required_fields_present
// ============================================================================

fn make_event(overrides: &[(&str, &str)]) -> StructuredSecurityLogEvent {
    let mut event = StructuredSecurityLogEvent {
        timestamp_ns: 42,
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
    for (field, value) in overrides {
        match *field {
            "trace_id" => event.trace_id = value.to_string(),
            "component" => event.component = value.to_string(),
            "event_type" => event.event_type = value.to_string(),
            "outcome" => event.outcome = value.to_string(),
            "principal_id" => event.principal_id = value.to_string(),
            "decision_id" => event.decision_id = value.to_string(),
            "policy_id" => event.policy_id = value.to_string(),
            "zone_id" => event.zone_id = value.to_string(),
            _ => {}
        }
    }
    event
}

#[test]
fn required_fields_present_true_with_all_filled() {
    assert!(make_event(&[]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_trace_id_empty() {
    assert!(!make_event(&[("trace_id", "")]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_component_empty() {
    assert!(!make_event(&[("component", "")]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_event_type_empty() {
    assert!(!make_event(&[("event_type", "")]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_outcome_empty() {
    assert!(!make_event(&[("outcome", "")]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_principal_id_empty() {
    assert!(!make_event(&[("principal_id", "")]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_decision_id_empty() {
    assert!(!make_event(&[("decision_id", "")]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_policy_id_empty() {
    assert!(!make_event(&[("policy_id", "")]).required_fields_present());
}

#[test]
fn required_fields_present_false_when_zone_id_empty() {
    assert!(!make_event(&[("zone_id", "")]).required_fields_present());
}

// ============================================================================
// Section 4: RuntimeSecurityMetrics — defaults, prometheus, serde
// ============================================================================

#[test]
fn metrics_default_zeroed_counters_for_all_enum_keys() {
    let m = RuntimeSecurityMetrics::default();
    assert_eq!(m.auth_failure_total.len(), AuthFailureType::ALL.len());
    assert_eq!(
        m.capability_denial_total.len(),
        CapabilityDenialReason::ALL.len()
    );
    assert_eq!(m.replay_drop_total.len(), ReplayDropReason::ALL.len());
    assert_eq!(
        m.checkpoint_violation_total.len(),
        CheckpointViolationType::ALL.len()
    );
    assert_eq!(
        m.revocation_check_total.len(),
        RevocationCheckOutcome::ALL.len()
    );
    assert_eq!(
        m.cross_zone_reference_total.len(),
        CrossZoneReferenceType::ALL.len()
    );
    assert_eq!(m.revocation_freshness_degraded_seconds, 0);
    // All counters are zero.
    for v in m.auth_failure_total.values() {
        assert_eq!(*v, 0);
    }
}

#[test]
fn metrics_prometheus_output_contains_help_type_and_value_lines() {
    let m = RuntimeSecurityMetrics::default();
    let prom = m.to_prometheus();
    // Every metric family must have HELP, TYPE, and at least one value line.
    assert!(prom.contains("# HELP auth_failure_total"));
    assert!(prom.contains("# TYPE auth_failure_total counter"));
    assert!(prom.contains("auth_failure_total{type=\"signature_invalid\"} 0"));
    assert!(prom.contains("# TYPE revocation_freshness_degraded_seconds gauge"));
    assert!(prom.contains("revocation_freshness_degraded_seconds 0"));
    assert!(prom.contains("# HELP cross_zone_reference_total"));
}

#[test]
fn metrics_prometheus_reflects_non_zero_values() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyExpired, None, None);
    obs.record_auth_failure(ctx(2), AuthFailureType::KeyExpired, None, None);
    let prom = obs.metrics().to_prometheus();
    assert!(prom.contains("auth_failure_total{type=\"key_expired\"} 2"));
}

#[test]
fn metrics_serde_roundtrip() {
    let m = RuntimeSecurityMetrics::default();
    let json = serde_json::to_string(&m).unwrap();
    let back: RuntimeSecurityMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

// ============================================================================
// Section 5: RuntimeSecurityObservability — construction and accessors
// ============================================================================

#[test]
fn new_observability_has_empty_logs_and_zeroed_metrics() {
    let obs = RuntimeSecurityObservability::new();
    assert!(obs.logs().is_empty());
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 0);
}

#[test]
fn default_and_new_are_equivalent() {
    let a = RuntimeSecurityObservability::new();
    let b = RuntimeSecurityObservability::default();
    assert_eq!(a, b);
}

// ============================================================================
// Section 6: record_auth_failure
// ============================================================================

#[test]
fn record_auth_failure_signature_invalid_event_fields() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_auth_failure(
        ctx(100),
        AuthFailureType::SignatureInvalid,
        Some("raw-key"),
        Some("raw-token"),
    );
    assert_eq!(event.event_type, "auth_failure");
    assert_eq!(event.outcome, "denied");
    assert!(event.error_code.is_some());
    assert_eq!(event.timestamp_ns, 100);
    assert_eq!(event.trace_id, "trace-100");
    // key_material is redacted
    let km = event.metadata.get("key_material_hash").unwrap();
    assert!(km.starts_with("sha256:"));
    assert!(!km.contains("raw-key"));
    // token content is redacted
    let tc = event.metadata.get("token_content_hash").unwrap();
    assert!(tc.starts_with("sha256:"));
    assert!(!tc.contains("raw-token"));
    // Metric incremented
    assert_eq!(
        *obs.metrics()
            .auth_failure_total
            .get(&AuthFailureType::SignatureInvalid)
            .unwrap(),
        1
    );
}

#[test]
fn record_auth_failure_without_optional_material() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_auth_failure(ctx(200), AuthFailureType::AttestationInvalid, None, None);
    assert!(!event.metadata.contains_key("key_material_hash"));
    assert!(!event.metadata.contains_key("token_content_hash"));
    assert!(event.metadata.contains_key("failure_type"));
}

#[test]
fn record_auth_failure_with_empty_context_fields_sanitized() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_auth_failure(empty_ctx(), AuthFailureType::KeyRevoked, None, None);
    // Sanitized fallbacks
    assert_eq!(event.trace_id, "trace-missing");
    assert_eq!(event.principal_id, "principal-missing");
    assert_eq!(event.decision_id, "decision-missing");
    assert_eq!(event.policy_id, "policy-missing");
    assert_eq!(event.zone_id, "zone-missing");
    assert_eq!(event.component, "runtime_observability");
    assert!(event.required_fields_present());
}

// ============================================================================
// Section 7: record_capability_denial
// ============================================================================

#[test]
fn record_capability_denial_all_reasons() {
    let mut obs = RuntimeSecurityObservability::new();
    for reason in CapabilityDenialReason::ALL {
        let event = obs.record_capability_denial(ctx(300), reason, "some_cap");
        assert_eq!(event.event_type, "capability_denial");
        assert_eq!(event.outcome, "denied");
        assert!(event.error_code.is_some());
        assert_eq!(
            event.metadata.get("denial_reason").unwrap(),
            &reason.to_string()
        );
        assert_eq!(
            event.metadata.get("requested_capability").unwrap(),
            "some_cap"
        );
    }
    // All 6 reasons incremented once each
    for reason in CapabilityDenialReason::ALL {
        assert_eq!(
            *obs.metrics().capability_denial_total.get(&reason).unwrap(),
            1
        );
    }
}

#[test]
fn record_capability_denial_empty_capability_name_sanitized() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_capability_denial(ctx(301), CapabilityDenialReason::Expired, "");
    assert_eq!(
        event.metadata.get("requested_capability").unwrap(),
        "unspecified"
    );
}

// ============================================================================
// Section 8: record_replay_drop
// ============================================================================

#[test]
fn record_replay_drop_all_reasons() {
    let mut obs = RuntimeSecurityObservability::new();
    for reason in ReplayDropReason::ALL {
        let event = obs.record_replay_drop(ctx(400), reason, 10, 20, "sess-xyz");
        assert_eq!(event.event_type, "replay_drop");
        assert_eq!(event.outcome, "dropped");
        assert!(event.error_code.is_some());
        assert_eq!(event.metadata.get("received_seq").unwrap(), "10");
        assert_eq!(event.metadata.get("expected_seq").unwrap(), "20");
        let sid = event.metadata.get("session_id_hash").unwrap();
        assert!(sid.starts_with("sha256:"));
    }
    for reason in ReplayDropReason::ALL {
        assert_eq!(*obs.metrics().replay_drop_total.get(&reason).unwrap(), 1);
    }
}

// ============================================================================
// Section 9: record_checkpoint_violation
// ============================================================================

#[test]
fn record_checkpoint_violation_all_types() {
    let mut obs = RuntimeSecurityObservability::new();
    for vtype in CheckpointViolationType::ALL {
        let event = obs.record_checkpoint_violation(ctx(500), vtype, 3, 7);
        assert_eq!(event.event_type, "checkpoint_violation");
        assert_eq!(event.outcome, "rejected");
        assert!(event.error_code.is_some());
        assert_eq!(event.metadata.get("attempted_seq").unwrap(), "3");
        assert_eq!(event.metadata.get("current_seq").unwrap(), "7");
    }
    for vtype in CheckpointViolationType::ALL {
        assert_eq!(
            *obs.metrics()
                .checkpoint_violation_total
                .get(&vtype)
                .unwrap(),
            1
        );
    }
}

// ============================================================================
// Section 10: record_revocation_check
// ============================================================================

#[test]
fn record_revocation_check_pass_no_error_code() {
    let mut obs = RuntimeSecurityObservability::new();
    let event =
        obs.record_revocation_check(ctx(600), RevocationCheckOutcome::Pass, 100, 100, 50, None);
    assert_eq!(event.event_type, "revocation_check");
    assert_eq!(event.outcome, "pass");
    assert!(event.error_code.is_none());
    assert_eq!(event.metadata.get("staleness_gap").unwrap(), "0");
}

#[test]
fn record_revocation_check_revoked_has_error_code() {
    let mut obs = RuntimeSecurityObservability::new();
    let event =
        obs.record_revocation_check(ctx(601), RevocationCheckOutcome::Revoked, 80, 100, 50, None);
    assert_eq!(event.outcome, "denied");
    assert!(event.error_code.is_some());
    assert_eq!(event.metadata.get("staleness_gap").unwrap(), "20");
}

#[test]
fn record_revocation_check_stale_updates_degraded_seconds() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_revocation_check(
        ctx(602),
        RevocationCheckOutcome::Stale,
        50,
        100,
        60,
        Some(300),
    );
    assert_eq!(event.outcome, "degraded");
    assert!(event.error_code.is_some());
    assert_eq!(event.metadata.get("degraded_seconds").unwrap(), "300");
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 300);
}

#[test]
fn record_revocation_check_stale_without_degraded_seconds_uses_zero() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_revocation_check(ctx(603), RevocationCheckOutcome::Stale, 50, 100, 60, None);
    // When degraded_seconds is None, the gauge is set to 0.
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 0);
}

#[test]
fn record_revocation_check_staleness_gap_saturates_at_zero() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_revocation_check(
        ctx(604),
        RevocationCheckOutcome::Pass,
        200,
        100, // local ahead of expected
        50,
        None,
    );
    // saturating_sub ensures no underflow
    assert_eq!(event.metadata.get("staleness_gap").unwrap(), "0");
}

// ============================================================================
// Section 11: record_cross_zone_reference
// ============================================================================

#[test]
fn record_cross_zone_reference_provenance_allowed_no_error() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_cross_zone_reference(
        ctx(700),
        CrossZoneReferenceType::ProvenanceAllowed,
        "zone-src",
        "zone-tgt",
    );
    assert_eq!(event.event_type, "cross_zone_reference");
    assert_eq!(event.outcome, "allowed");
    assert!(event.error_code.is_none());
    assert_eq!(event.metadata.get("source_zone").unwrap(), "zone-src");
    assert_eq!(event.metadata.get("target_zone").unwrap(), "zone-tgt");
}

#[test]
fn record_cross_zone_reference_authority_denied_has_error() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_cross_zone_reference(
        ctx(701),
        CrossZoneReferenceType::AuthorityDenied,
        "zone-src",
        "zone-tgt",
    );
    assert_eq!(event.outcome, "denied");
    assert!(event.error_code.is_some());
}

#[test]
fn record_cross_zone_reference_empty_zones_sanitized() {
    let mut obs = RuntimeSecurityObservability::new();
    let event = obs.record_cross_zone_reference(
        ctx(702),
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

// ============================================================================
// Section 12: Log accumulation and export
// ============================================================================

#[test]
fn logs_accumulate_in_order() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyExpired, None, None);
    obs.record_capability_denial(ctx(2), CapabilityDenialReason::Expired, "cap");
    obs.record_replay_drop(ctx(3), ReplayDropReason::StaleSeq, 1, 2, "sid");
    assert_eq!(obs.logs().len(), 3);
    assert_eq!(obs.logs()[0].timestamp_ns, 1);
    assert_eq!(obs.logs()[1].timestamp_ns, 2);
    assert_eq!(obs.logs()[2].timestamp_ns, 3);
}

#[test]
fn export_logs_jsonl_empty_on_fresh_observability() {
    let obs = RuntimeSecurityObservability::new();
    assert!(obs.export_logs_jsonl().is_empty());
}

#[test]
fn export_logs_jsonl_produces_valid_json_per_line() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(10), AuthFailureType::SignatureInvalid, None, None);
    obs.record_checkpoint_violation(ctx(11), CheckpointViolationType::ForkDetected, 1, 2);
    let jsonl = obs.export_logs_jsonl();
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(parsed.is_object());
    }
}

// ============================================================================
// Section 13: JSONL render/parse round-trip
// ============================================================================

#[test]
fn render_parse_jsonl_roundtrip_with_multiple_event_types() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyRevoked, Some("k"), None);
    obs.record_capability_denial(ctx(2), CapabilityDenialReason::CeilingExceeded, "net");
    obs.record_replay_drop(ctx(3), ReplayDropReason::CrossSession, 5, 6, "s");
    obs.record_checkpoint_violation(ctx(4), CheckpointViolationType::QuorumInsufficient, 1, 2);
    obs.record_revocation_check(ctx(5), RevocationCheckOutcome::Revoked, 10, 20, 5, None);
    obs.record_cross_zone_reference(ctx(6), CrossZoneReferenceType::AuthorityDenied, "a", "b");

    let jsonl = render_security_logs_jsonl(obs.logs());
    let parsed = parse_security_logs_jsonl(&jsonl).unwrap();
    assert_eq!(parsed.len(), 6);
    // Verify each event matches the original
    for (original, restored) in obs.logs().iter().zip(parsed.iter()) {
        assert_eq!(original, restored);
    }
}

#[test]
fn parse_security_logs_jsonl_skips_blank_lines() {
    let parsed = parse_security_logs_jsonl("\n\n  \n").unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn parse_security_logs_jsonl_invalid_json_returns_error() {
    let result = parse_security_logs_jsonl("{bad json}");
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("line 1"));
}

#[test]
fn parse_security_logs_jsonl_error_includes_line_number() {
    // First line valid, second invalid.
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyExpired, None, None);
    let valid_line = serde_json::to_string(&obs.logs()[0]).unwrap();
    let input = format!("{valid_line}\nnot-json");
    let result = parse_security_logs_jsonl(&input);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("line 2"));
}

// ============================================================================
// Section 14: redact_sensitive_value
// ============================================================================

#[test]
fn redact_sensitive_value_deterministic_for_same_input() {
    let a = redact_sensitive_value("secret123");
    let b = redact_sensitive_value("secret123");
    assert_eq!(a, b);
}

#[test]
fn redact_sensitive_value_different_for_different_inputs() {
    assert_ne!(
        redact_sensitive_value("alpha"),
        redact_sensitive_value("beta")
    );
}

#[test]
fn redact_sensitive_value_format_is_sha256_colon_hex() {
    let redacted = redact_sensitive_value("test-material");
    assert!(redacted.starts_with("sha256:"));
    let hex_part = &redacted["sha256:".len()..];
    assert_eq!(hex_part.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn redact_sensitive_value_empty_string_still_produces_hash() {
    let redacted = redact_sensitive_value("");
    assert!(redacted.starts_with("sha256:"));
    let hex_part = &redacted["sha256:".len()..];
    assert_eq!(hex_part.len(), 64);
}

// ============================================================================
// Section 15: Cross-event accumulation and mixed scenarios
// ============================================================================

#[test]
fn mixed_events_accumulate_all_counters_independently() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::SignatureInvalid, None, None);
    obs.record_auth_failure(ctx(2), AuthFailureType::SignatureInvalid, None, None);
    obs.record_capability_denial(ctx(3), CapabilityDenialReason::InsufficientAuthority, "cap");
    obs.record_replay_drop(ctx(4), ReplayDropReason::DuplicateSeq, 1, 2, "s");
    obs.record_checkpoint_violation(ctx(5), CheckpointViolationType::RollbackAttempt, 1, 2);
    obs.record_revocation_check(ctx(6), RevocationCheckOutcome::Pass, 100, 100, 50, None);
    obs.record_cross_zone_reference(ctx(7), CrossZoneReferenceType::ProvenanceAllowed, "a", "b");

    let m = obs.metrics();
    assert_eq!(
        *m.auth_failure_total
            .get(&AuthFailureType::SignatureInvalid)
            .unwrap(),
        2
    );
    assert_eq!(
        *m.capability_denial_total
            .get(&CapabilityDenialReason::InsufficientAuthority)
            .unwrap(),
        1
    );
    assert_eq!(
        *m.replay_drop_total
            .get(&ReplayDropReason::DuplicateSeq)
            .unwrap(),
        1
    );
    assert_eq!(
        *m.checkpoint_violation_total
            .get(&CheckpointViolationType::RollbackAttempt)
            .unwrap(),
        1
    );
    assert_eq!(
        *m.revocation_check_total
            .get(&RevocationCheckOutcome::Pass)
            .unwrap(),
        1
    );
    assert_eq!(
        *m.cross_zone_reference_total
            .get(&CrossZoneReferenceType::ProvenanceAllowed)
            .unwrap(),
        1
    );
    assert_eq!(obs.logs().len(), 7);
}

#[test]
fn rapid_accumulation_does_not_overflow_counters() {
    let mut obs = RuntimeSecurityObservability::new();
    for i in 0..1000_u64 {
        obs.record_auth_failure(ctx(i), AuthFailureType::KeyExpired, None, None);
    }
    assert_eq!(
        *obs.metrics()
            .auth_failure_total
            .get(&AuthFailureType::KeyExpired)
            .unwrap(),
        1000
    );
    assert_eq!(obs.logs().len(), 1000);
}

#[test]
fn revocation_degraded_seconds_overwritten_by_latest_stale_event() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_revocation_check(
        ctx(1),
        RevocationCheckOutcome::Stale,
        50,
        100,
        60,
        Some(100),
    );
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 100);
    obs.record_revocation_check(
        ctx(2),
        RevocationCheckOutcome::Stale,
        50,
        100,
        60,
        Some(200),
    );
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 200);
    // A Pass event does NOT reset the gauge.
    obs.record_revocation_check(ctx(3), RevocationCheckOutcome::Pass, 100, 100, 60, None);
    assert_eq!(obs.metrics().revocation_freshness_degraded_seconds, 200);
}

// ============================================================================
// Section 16: Serde roundtrips for aggregate structures
// ============================================================================

#[test]
fn observability_serde_roundtrip_with_events() {
    let mut obs = RuntimeSecurityObservability::new();
    obs.record_auth_failure(ctx(1), AuthFailureType::KeyExpired, Some("k"), Some("t"));
    obs.record_capability_denial(ctx(2), CapabilityDenialReason::Expired, "net");
    obs.record_revocation_check(ctx(3), RevocationCheckOutcome::Stale, 10, 20, 5, Some(42));

    let json = serde_json::to_string(&obs).unwrap();
    let back: RuntimeSecurityObservability = serde_json::from_str(&json).unwrap();
    assert_eq!(back, obs);
}

#[test]
fn structured_log_event_serde_roundtrip() {
    let event = make_event(&[]);
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredSecurityLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn structured_log_event_with_error_code_serde_roundtrip() {
    let mut event = make_event(&[]);
    event.error_code = Some("FE-1001".to_string());
    event.metadata.insert("k1".to_string(), "v1".to_string());
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredSecurityLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ============================================================================
// Section 17: Prometheus output correctness
// ============================================================================

#[test]
fn prometheus_output_all_auth_failure_labels_present() {
    let prom = RuntimeSecurityMetrics::default().to_prometheus();
    for variant in AuthFailureType::ALL {
        let expected = format!("auth_failure_total{{type=\"{}\"}} 0", variant.as_label());
        assert!(prom.contains(&expected), "missing: {expected}");
    }
}

#[test]
fn prometheus_output_all_capability_denial_labels_present() {
    let prom = RuntimeSecurityMetrics::default().to_prometheus();
    for variant in CapabilityDenialReason::ALL {
        let expected = format!(
            "capability_denial_total{{reason=\"{}\"}} 0",
            variant.as_label()
        );
        assert!(prom.contains(&expected), "missing: {expected}");
    }
}

#[test]
fn prometheus_output_all_replay_drop_labels_present() {
    let prom = RuntimeSecurityMetrics::default().to_prometheus();
    for variant in ReplayDropReason::ALL {
        let expected = format!("replay_drop_total{{reason=\"{}\"}} 0", variant.as_label());
        assert!(prom.contains(&expected), "missing: {expected}");
    }
}

#[test]
fn prometheus_output_all_checkpoint_violation_labels_present() {
    let prom = RuntimeSecurityMetrics::default().to_prometheus();
    for variant in CheckpointViolationType::ALL {
        let expected = format!(
            "checkpoint_violation_total{{type=\"{}\"}} 0",
            variant.as_label()
        );
        assert!(prom.contains(&expected), "missing: {expected}");
    }
}

#[test]
fn prometheus_output_all_revocation_check_labels_present() {
    let prom = RuntimeSecurityMetrics::default().to_prometheus();
    for variant in RevocationCheckOutcome::ALL {
        let expected = format!(
            "revocation_check_total{{outcome=\"{}\"}} 0",
            variant.as_label()
        );
        assert!(prom.contains(&expected), "missing: {expected}");
    }
}

#[test]
fn prometheus_output_all_cross_zone_labels_present() {
    let prom = RuntimeSecurityMetrics::default().to_prometheus();
    for variant in CrossZoneReferenceType::ALL {
        let expected = format!(
            "cross_zone_reference_total{{type=\"{}\"}} 0",
            variant.as_label()
        );
        assert!(prom.contains(&expected), "missing: {expected}");
    }
}

// ============================================================================
// Section 18: Error codes per event type
// ============================================================================

#[test]
fn auth_failure_error_codes_follow_fe_pattern() {
    let mut obs = RuntimeSecurityObservability::new();
    for variant in AuthFailureType::ALL {
        let event = obs.record_auth_failure(ctx(800), variant, None, None);
        let code = event.error_code.unwrap();
        assert!(code.starts_with("FE-"), "code={code}");
    }
}

#[test]
fn capability_denial_error_codes_follow_fe_pattern() {
    let mut obs = RuntimeSecurityObservability::new();
    for reason in CapabilityDenialReason::ALL {
        let event = obs.record_capability_denial(ctx(801), reason, "c");
        let code = event.error_code.unwrap();
        assert!(code.starts_with("FE-"), "code={code}");
    }
}

#[test]
fn replay_drop_error_codes_follow_fe_pattern() {
    let mut obs = RuntimeSecurityObservability::new();
    for reason in ReplayDropReason::ALL {
        let event = obs.record_replay_drop(ctx(802), reason, 1, 2, "s");
        let code = event.error_code.unwrap();
        assert!(code.starts_with("FE-"), "code={code}");
    }
}

#[test]
fn checkpoint_violation_error_codes_follow_fe_pattern() {
    let mut obs = RuntimeSecurityObservability::new();
    for vtype in CheckpointViolationType::ALL {
        let event = obs.record_checkpoint_violation(ctx(803), vtype, 1, 2);
        let code = event.error_code.unwrap();
        assert!(code.starts_with("FE-"), "code={code}");
    }
}

// ============================================================================
// Section 19: SecurityEventContext serde
// ============================================================================

#[test]
fn security_event_context_serde_roundtrip() {
    let c = ctx(42);
    let json = serde_json::to_string(&c).unwrap();
    let back: SecurityEventContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}
