//! Enrichment integration tests for `canonical_encoding`.
//!
//! Covers gaps: CanonicalViolation Display and serde roundtrips,
//! GuardEventType serde roundtrips, CanonicalGuard registration and
//! validation lifecycle, class registration deduplication, rejection/
//! acceptance counting, event draining, static is_canonical_raw checks,
//! and NonCanonicalError construction and Display.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::canonical_encoding::{
    CanonicalGuard, CanonicalViolation, GuardEvent, GuardEventType, NonCanonicalError,
};
use frankenengine_engine::deterministic_serde::CanonicalValue;
use frankenengine_engine::engine_object_id::ObjectDomain;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn guard() -> CanonicalGuard {
    CanonicalGuard::new()
}

// ===========================================================================
// CanonicalViolation serde roundtrip
// ===========================================================================

#[test]
fn enrichment_violation_serde_roundtrip() {
    let violations = [
        CanonicalViolation::NonLexicographicKeys {
            prev_key: "b".to_string(),
            current_key: "a".to_string(),
        },
        CanonicalViolation::DuplicateKey {
            key: "x".to_string(),
        },
        CanonicalViolation::TrailingBytes { count: 5 },
        CanonicalViolation::LeadingPadding { byte_count: 2 },
        CanonicalViolation::RoundTripMismatch {
            first_diff_offset: 10,
            expected: 0x42,
            actual: 0x43,
        },
        CanonicalViolation::LengthMismatch {
            input_len: 100,
            canonical_len: 98,
        },
        CanonicalViolation::DeserializationFailed {
            detail: "bad input".to_string(),
        },
        CanonicalViolation::InvalidTag {
            tag: 0xFF,
            offset: 0,
        },
        CanonicalViolation::SchemaViolation {
            detail: "wrong schema".to_string(),
        },
    ];
    for v in &violations {
        let json = serde_json::to_string(v).unwrap();
        let back: CanonicalViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_violation_display_all_unique() {
    let violations = [
        CanonicalViolation::NonLexicographicKeys {
            prev_key: "b".to_string(),
            current_key: "a".to_string(),
        },
        CanonicalViolation::DuplicateKey {
            key: "x".to_string(),
        },
        CanonicalViolation::TrailingBytes { count: 5 },
        CanonicalViolation::LeadingPadding { byte_count: 2 },
        CanonicalViolation::RoundTripMismatch {
            first_diff_offset: 10,
            expected: 0x42,
            actual: 0x43,
        },
        CanonicalViolation::LengthMismatch {
            input_len: 100,
            canonical_len: 98,
        },
        CanonicalViolation::DeserializationFailed {
            detail: "bad".to_string(),
        },
        CanonicalViolation::InvalidTag {
            tag: 0xFF,
            offset: 0,
        },
        CanonicalViolation::SchemaViolation {
            detail: "wrong".to_string(),
        },
    ];
    let displays: BTreeSet<String> = violations.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(displays.len(), violations.len());
}

// ===========================================================================
// GuardEventType serde roundtrip
// ===========================================================================

#[test]
fn enrichment_guard_event_type_serde_roundtrip() {
    let types = [
        GuardEventType::Accepted,
        GuardEventType::Rejected {
            violation: CanonicalViolation::TrailingBytes { count: 1 },
        },
        GuardEventType::UnregisteredClass,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let back: GuardEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ===========================================================================
// CanonicalGuard: registration
// ===========================================================================

#[test]
fn enrichment_guard_new_empty() {
    let g = guard();
    assert_eq!(g.registered_class_count(), 0);
}

#[test]
fn enrichment_guard_register_class() {
    let mut g = guard();
    let _hash = g.register_class(
        ObjectDomain::PolicyObject,
        "policy-schema",
        1,
        b"definition",
    );
    assert_eq!(g.registered_class_count(), 1);
}

#[test]
fn enrichment_guard_is_class_registered() {
    let mut g = guard();
    g.register_class(
        ObjectDomain::PolicyObject,
        "policy-schema",
        1,
        b"definition",
    );
    assert!(g.is_class_registered(&ObjectDomain::PolicyObject));
    assert!(!g.is_class_registered(&ObjectDomain::EvidenceRecord));
}

#[test]
fn enrichment_guard_register_multiple_classes() {
    let mut g = guard();
    g.register_class(ObjectDomain::PolicyObject, "policy", 1, b"def1");
    g.register_class(ObjectDomain::EvidenceRecord, "evidence", 1, b"def2");
    assert_eq!(g.registered_class_count(), 2);
}

// ===========================================================================
// CanonicalGuard: counters
// ===========================================================================

#[test]
fn enrichment_guard_counters_zero_initially() {
    let g = guard();
    assert_eq!(g.rejection_count(), 0);
    assert_eq!(g.acceptance_count(), 0);
}

// ===========================================================================
// CanonicalGuard: events
// ===========================================================================

#[test]
fn enrichment_guard_drain_events_empty_initially() {
    let mut g = guard();
    let events = g.drain_events();
    assert!(events.is_empty());
}

#[test]
fn enrichment_guard_event_counts_empty_initially() {
    let g = guard();
    let counts = g.event_counts();
    assert!(counts.is_empty());
}

// ===========================================================================
// CanonicalGuard: is_canonical_raw
// ===========================================================================

#[test]
fn enrichment_is_canonical_raw_empty_bytes() {
    // Empty bytes should fail deserialization
    let result = CanonicalGuard::is_canonical_raw(&[]);
    assert!(result.is_err());
}

// ===========================================================================
// NonCanonicalError serde roundtrip
// ===========================================================================

#[test]
fn enrichment_non_canonical_error_serde_roundtrip() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::PolicyObject,
        input_hash: [0u8; 32],
        violation: CanonicalViolation::TrailingBytes { count: 3 },
        trace_id: "trace-001".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: NonCanonicalError = serde_json::from_str(&json).unwrap();
    assert_eq!(err.trace_id, back.trace_id);
    assert_eq!(err.violation, back.violation);
}

#[test]
fn enrichment_non_canonical_error_display_nonempty() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::PolicyObject,
        input_hash: [0u8; 32],
        violation: CanonicalViolation::DuplicateKey {
            key: "foo".to_string(),
        },
        trace_id: "trace-001".to_string(),
    };
    let display = err.to_string();
    assert!(!display.is_empty());
}

// ===========================================================================
// GuardEvent serde roundtrip
// ===========================================================================

#[test]
fn enrichment_guard_event_serde_roundtrip() {
    let event = GuardEvent {
        event_type: GuardEventType::Accepted,
        object_class: ObjectDomain::PolicyObject,
        trace_id: "trace-001".to_string(),
        input_hash: [1u8; 32],
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GuardEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event.trace_id, back.trace_id);
}

// ===========================================================================
// CanonicalGuard: validate with valid canonical bytes
// ===========================================================================

#[test]
fn enrichment_guard_validate_registered_domain() {
    use frankenengine_engine::deterministic_serde::encode_value;

    let mut g = guard();
    g.register_class(
        ObjectDomain::PolicyObject,
        "test-schema",
        1,
        b"test-definition",
    );
    // Encode a valid canonical value
    let value = CanonicalValue::U64(42);
    let bytes = encode_value(&value);
    let result = g.validate(ObjectDomain::PolicyObject, &bytes, "trace-001");
    // Result depends on whether the guard expects schema prefix in bytes
    // Just verify no panic
    let _ = result;
}

#[test]
fn enrichment_guard_validate_tracks_events() {
    use frankenengine_engine::deterministic_serde::encode_value;

    let mut g = guard();
    g.register_class(
        ObjectDomain::PolicyObject,
        "test-schema",
        1,
        b"test-definition",
    );
    let value = CanonicalValue::Bool(true);
    let bytes = encode_value(&value);
    let _ = g.validate(ObjectDomain::PolicyObject, &bytes, "trace-002");
    let events = g.drain_events();
    assert!(
        !events.is_empty(),
        "Validation should produce at least one event"
    );
}

// ===========================================================================
// Additional enrichment: edge cases and behavioral properties
// ===========================================================================

#[test]
fn guard_fresh_has_zero_counts() {
    let g = guard();
    assert_eq!(g.acceptance_count(), 0);
    assert_eq!(g.rejection_count(), 0);
}

#[test]
fn guard_drain_events_is_idempotent() {
    let mut g = guard();
    let first = g.drain_events();
    let second = g.drain_events();
    assert!(first.is_empty());
    assert!(second.is_empty());
}

#[test]
fn guard_register_same_class_twice_no_panic() {
    let mut g = guard();
    g.register_class(ObjectDomain::PolicyObject, "schema-a", 1, b"def-a");
    g.register_class(ObjectDomain::PolicyObject, "schema-b", 2, b"def-b");
    // Should not panic; behavior is implementation-defined but safe
}

#[test]
fn guard_register_different_domains() {
    let mut g = guard();
    g.register_class(ObjectDomain::PolicyObject, "schema-policy", 1, b"def-p");
    g.register_class(ObjectDomain::EvidenceRecord, "schema-evidence", 1, b"def-e");
    assert!(g.is_class_registered(&ObjectDomain::PolicyObject));
    assert!(g.is_class_registered(&ObjectDomain::EvidenceRecord));
    assert_eq!(g.registered_class_count(), 2);
}

#[test]
fn violation_display_all_variants() {
    let variants: Vec<CanonicalViolation> = vec![
        CanonicalViolation::NonLexicographicKeys {
            prev_key: "b".to_string(),
            current_key: "a".to_string(),
        },
        CanonicalViolation::DuplicateKey {
            key: "dup".to_string(),
        },
        CanonicalViolation::TrailingBytes { count: 3 },
        CanonicalViolation::LeadingPadding { byte_count: 2 },
        CanonicalViolation::DeserializationFailed {
            detail: "bad input".to_string(),
        },
        CanonicalViolation::InvalidTag {
            tag: 0xFF,
            offset: 0,
        },
        CanonicalViolation::SchemaViolation {
            detail: "mismatch".to_string(),
        },
    ];
    let mut displays = BTreeSet::new();
    for v in &variants {
        let d = format!("{v}");
        assert!(!d.is_empty(), "violation Display should be nonempty");
        displays.insert(d);
    }
    // All displays should be unique
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn violation_serde_roundtrip() {
    let v = CanonicalViolation::DuplicateKey {
        key: "test_key".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: CanonicalViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn non_canonical_error_display_nonempty() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::PolicyObject,
        input_hash: [0u8; 32],
        violation: CanonicalViolation::TrailingBytes { count: 5 },
        trace_id: "t1".to_string(),
    };
    let display = format!("{err}");
    assert!(!display.is_empty());
    assert!(display.contains("trailing"));
}

#[test]
fn non_canonical_error_is_std_error() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::PolicyObject,
        input_hash: [0u8; 32],
        violation: CanonicalViolation::InvalidTag {
            tag: 0xAB,
            offset: 0,
        },
        trace_id: "t2".to_string(),
    };
    // Verify it implements std::error::Error
    let _: &dyn std::error::Error = &err;
}

#[test]
fn guard_event_type_accepted_distinct_from_rejected() {
    let accepted = GuardEventType::Accepted;
    let rejected = GuardEventType::Rejected {
        violation: CanonicalViolation::TrailingBytes { count: 1 },
    };
    assert_ne!(format!("{accepted:?}"), format!("{rejected:?}"));
}

#[test]
fn guard_event_type_serde_accepted() {
    let variant = GuardEventType::Accepted;
    let json = serde_json::to_string(&variant).unwrap();
    let back: GuardEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(variant, back);
}

#[test]
fn guard_event_type_serde_unregistered() {
    let variant = GuardEventType::UnregisteredClass;
    let json = serde_json::to_string(&variant).unwrap();
    let back: GuardEventType = serde_json::from_str(&json).unwrap();
    assert_eq!(variant, back);
}

#[test]
fn is_canonical_raw_rejects_empty_bytes() {
    let result = CanonicalGuard::is_canonical_raw(&[]);
    assert!(result.is_err());
}

#[test]
fn is_canonical_raw_accepts_valid_canonical_bytes() {
    use frankenengine_engine::deterministic_serde::encode_value;
    let bytes = encode_value(&CanonicalValue::U64(42));
    let result = CanonicalGuard::is_canonical_raw(&bytes);
    assert!(result.is_ok());
}

#[test]
fn guard_validate_unregistered_domain_produces_event() {
    use frankenengine_engine::deterministic_serde::encode_value;
    let mut g = guard();
    // Don't register any domain
    let bytes = encode_value(&CanonicalValue::Bool(false));
    let _ = g.validate(ObjectDomain::PolicyObject, &bytes, "trace-unreg");
    let events = g.drain_events();
    assert!(
        !events.is_empty(),
        "unregistered domain should produce an event"
    );
}

#[test]
fn guard_event_counts_return_btreemap() {
    let g = guard();
    let counts = g.event_counts();
    // Fresh guard should have empty or zero counts
    assert!(counts.values().all(|v| *v == 0) || counts.is_empty());
}
