#![forbid(unsafe_code)]
//! Integration tests for `canonical_encoding` — enforcement wrapper, violation
//! detection, audit events, multi-class registration, serde round-trips,
//! deterministic behavior, `CanonicalityCheck` trait, and edge cases.

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

use std::collections::BTreeMap;

use frankenengine_engine::canonical_encoding::{
    CanonicalGuard, CanonicalViolation, CanonicalityCheck, GuardEvent, GuardEventType,
    NonCanonicalError,
};
use frankenengine_engine::deterministic_serde::{
    CanonicalValue, SchemaHash, encode_value, serialize_with_schema,
};
use frankenengine_engine::engine_object_id::ObjectDomain;
use frankenengine_engine::hash_tiers::ContentHash;

// ── helpers ────────────────────────────────────────────────────────────────

/// Create a fresh guard with a single PolicyObject class registered.
fn setup_guard() -> (CanonicalGuard, SchemaHash) {
    let mut guard = CanonicalGuard::new();
    let schema = guard.register_class(
        ObjectDomain::PolicyObject,
        "TestPolicy",
        1,
        b"test-policy-schema-v1",
    );
    (guard, schema)
}

/// Create a valid canonical payload for the given schema and value.
fn make_canonical_payload(schema: &SchemaHash, value: &CanonicalValue) -> Vec<u8> {
    serialize_with_schema(schema, value)
}

/// Compute a content hash of raw bytes (mirroring the module's internal fn).
fn compute_input_hash(bytes: &[u8]) -> [u8; 32] {
    *ContentHash::compute(bytes).as_bytes()
}

// ── CanonicalViolation Display ─────────────────────────────────────────────

#[test]
fn violation_display_non_lexicographic_keys() {
    let v = CanonicalViolation::NonLexicographicKeys {
        prev_key: "z".to_string(),
        current_key: "a".to_string(),
    };
    let s = v.to_string();
    assert!(s.contains("non-lexicographic"), "got: {s}");
    assert!(s.contains("'z'"), "got: {s}");
    assert!(s.contains("'a'"), "got: {s}");
}

#[test]
fn violation_display_duplicate_key() {
    let v = CanonicalViolation::DuplicateKey {
        key: "mykey".to_string(),
    };
    let s = v.to_string();
    assert!(s.contains("duplicate"), "got: {s}");
    assert!(s.contains("mykey"), "got: {s}");
}

#[test]
fn violation_display_trailing_bytes() {
    let v = CanonicalViolation::TrailingBytes { count: 42 };
    let s = v.to_string();
    assert!(s.contains("42"), "got: {s}");
    assert!(s.contains("trailing"), "got: {s}");
}

#[test]
fn violation_display_leading_padding() {
    let v = CanonicalViolation::LeadingPadding { byte_count: 7 };
    let s = v.to_string();
    assert!(s.contains("7"), "got: {s}");
    assert!(s.contains("padding"), "got: {s}");
}

#[test]
fn violation_display_round_trip_mismatch() {
    let v = CanonicalViolation::RoundTripMismatch {
        first_diff_offset: 10,
        expected: 0x41,
        actual: 0x42,
    };
    let s = v.to_string();
    assert!(s.contains("10"), "got: {s}");
    assert!(s.contains("0x41"), "got: {s}");
    assert!(s.contains("0x42"), "got: {s}");
}

#[test]
fn violation_display_length_mismatch() {
    let v = CanonicalViolation::LengthMismatch {
        input_len: 100,
        canonical_len: 99,
    };
    let s = v.to_string();
    assert!(s.contains("100"), "got: {s}");
    assert!(s.contains("99"), "got: {s}");
}

#[test]
fn violation_display_deserialization_failed() {
    let v = CanonicalViolation::DeserializationFailed {
        detail: "parse error".to_string(),
    };
    let s = v.to_string();
    assert!(s.contains("deserialization failed"), "got: {s}");
    assert!(s.contains("parse error"), "got: {s}");
}

#[test]
fn violation_display_invalid_tag() {
    let v = CanonicalViolation::InvalidTag {
        tag: 0xFE,
        offset: 32,
    };
    let s = v.to_string();
    assert!(s.contains("0xfe"), "got: {s}");
    assert!(s.contains("32"), "got: {s}");
}

#[test]
fn violation_display_schema_violation() {
    let v = CanonicalViolation::SchemaViolation {
        detail: "mismatch".to_string(),
    };
    let s = v.to_string();
    assert!(s.contains("schema violation"), "got: {s}");
    assert!(s.contains("mismatch"), "got: {s}");
}

// ── NonCanonicalError Display & Error ──────────────────────────────────────

#[test]
fn non_canonical_error_display_format() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::PolicyObject,
        input_hash: [0u8; 32],
        violation: CanonicalViolation::TrailingBytes { count: 3 },
        trace_id: "trace-xyz".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("policy_object"), "got: {display}");
    assert!(display.contains("trailing"), "got: {display}");
    assert!(display.contains("trace-xyz"), "got: {display}");
}

#[test]
fn non_canonical_error_is_std_error() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::EvidenceRecord,
        input_hash: [0xAB; 32],
        violation: CanonicalViolation::DuplicateKey {
            key: "k".to_string(),
        },
        trace_id: "t-err".to_string(),
    };
    // Verify it implements std::error::Error by using it as a trait object.
    let boxed: Box<dyn std::error::Error> = Box::new(err.clone());
    assert!(boxed.to_string().contains("evidence_record"));
}

#[test]
fn non_canonical_error_different_domains() {
    let domains = [
        ObjectDomain::PolicyObject,
        ObjectDomain::EvidenceRecord,
        ObjectDomain::Revocation,
        ObjectDomain::SignedManifest,
        ObjectDomain::Attestation,
        ObjectDomain::CapabilityToken,
        ObjectDomain::CheckpointArtifact,
        ObjectDomain::RecoveryArtifact,
        ObjectDomain::KeyBundle,
    ];
    for domain in &domains {
        let err = NonCanonicalError {
            object_class: *domain,
            input_hash: [0u8; 32],
            violation: CanonicalViolation::TrailingBytes { count: 1 },
            trace_id: "t-domain".to_string(),
        };
        let s = err.to_string();
        // Display must mention the domain name.
        assert!(
            s.contains(&domain.to_string()),
            "domain {domain} not in: {s}"
        );
    }
}

// ── GuardEventType Display ─────────────────────────────────────────────────

#[test]
fn guard_event_type_display_accepted() {
    assert_eq!(GuardEventType::Accepted.to_string(), "accepted");
}

#[test]
fn guard_event_type_display_rejected() {
    let evt = GuardEventType::Rejected {
        violation: CanonicalViolation::TrailingBytes { count: 1 },
    };
    let s = evt.to_string();
    assert!(s.contains("rejected"), "got: {s}");
    assert!(s.contains("trailing"), "got: {s}");
}

#[test]
fn guard_event_type_display_unregistered_class() {
    let s = GuardEventType::UnregisteredClass.to_string();
    assert!(s.contains("unregistered"), "got: {s}");
}

// ── CanonicalGuard: construction and defaults ──────────────────────────────

#[test]
fn guard_new_is_empty() {
    let guard = CanonicalGuard::new();
    assert_eq!(guard.registered_class_count(), 0);
    assert_eq!(guard.acceptance_count(), 0);
    assert_eq!(guard.rejection_count(), 0);
}

#[test]
fn guard_default_is_same_as_new() {
    let guard = CanonicalGuard::default();
    assert_eq!(guard.registered_class_count(), 0);
    assert_eq!(guard.acceptance_count(), 0);
    assert_eq!(guard.rejection_count(), 0);
}

// ── Class registration ─────────────────────────────────────────────────────

#[test]
fn register_single_class() {
    let (guard, _schema) = setup_guard();
    assert_eq!(guard.registered_class_count(), 1);
    assert!(guard.is_class_registered(&ObjectDomain::PolicyObject));
    assert!(!guard.is_class_registered(&ObjectDomain::EvidenceRecord));
}

#[test]
fn register_multiple_classes() {
    let mut guard = CanonicalGuard::new();
    let s1 = guard.register_class(ObjectDomain::PolicyObject, "Policy", 1, b"policy-v1");
    let s2 = guard.register_class(ObjectDomain::EvidenceRecord, "Evidence", 1, b"evidence-v1");
    let s3 = guard.register_class(ObjectDomain::Revocation, "Revocation", 1, b"revocation-v1");

    assert_eq!(guard.registered_class_count(), 3);
    assert!(guard.is_class_registered(&ObjectDomain::PolicyObject));
    assert!(guard.is_class_registered(&ObjectDomain::EvidenceRecord));
    assert!(guard.is_class_registered(&ObjectDomain::Revocation));
    assert!(!guard.is_class_registered(&ObjectDomain::SignedManifest));

    // Schema hashes must be distinct for different definitions.
    assert_ne!(s1, s2);
    assert_ne!(s2, s3);
    assert_ne!(s1, s3);
}

#[test]
fn register_same_class_twice_overwrites() {
    let mut guard = CanonicalGuard::new();
    let s1 = guard.register_class(ObjectDomain::PolicyObject, "PolicyV1", 1, b"schema-v1");
    let s2 = guard.register_class(ObjectDomain::PolicyObject, "PolicyV2", 2, b"schema-v2");

    // Still one registered class.
    assert_eq!(guard.registered_class_count(), 1);
    // But the schema hash changed.
    assert_ne!(s1, s2);
}

#[test]
fn same_definition_yields_same_schema_hash() {
    let mut guard = CanonicalGuard::new();
    let s1 = guard.register_class(ObjectDomain::PolicyObject, "P", 1, b"same-def");
    let s2 = guard.register_class(ObjectDomain::EvidenceRecord, "E", 1, b"same-def");
    // SchemaHash from_definition is deterministic.
    assert_eq!(s1, s2);
}

// ── Validate: basic acceptance ─────────────────────────────────────────────

#[test]
fn validate_accepts_u64() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::U64(42);
    let bytes = make_canonical_payload(&schema, &val);
    let result = guard.validate(ObjectDomain::PolicyObject, &bytes, "t-u64");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), val);
    assert_eq!(guard.acceptance_count(), 1);
    assert_eq!(guard.rejection_count(), 0);
}

#[test]
fn validate_accepts_i64() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::I64(-999);
    let bytes = make_canonical_payload(&schema, &val);
    let result = guard.validate(ObjectDomain::PolicyObject, &bytes, "t-i64");
    assert_eq!(result.unwrap(), val);
}

#[test]
fn validate_accepts_bool_true() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Bool(true);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-bt")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_bool_false() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Bool(false);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-bf")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_string() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::String("hello world".to_string());
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-str")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_empty_string() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::String(String::new());
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-empty-str")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_unicode_string() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::String("unicode: \u{1F600}\u{1F4A9}".to_string());
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-unicode")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_bytes() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-bytes")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_empty_bytes() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Bytes(vec![]);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-empty-bytes")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_null() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Null;
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-null")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_empty_array() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Array(vec![]);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-empty-arr")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_heterogeneous_array() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Array(vec![
        CanonicalValue::U64(1),
        CanonicalValue::String("two".to_string()),
        CanonicalValue::Bool(false),
        CanonicalValue::Null,
    ]);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-het-arr")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_empty_map() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Map(BTreeMap::new());
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-empty-map")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_map_with_entries() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Map(BTreeMap::from([
        ("alpha".to_string(), CanonicalValue::U64(1)),
        ("beta".to_string(), CanonicalValue::Bool(true)),
        ("gamma".to_string(), CanonicalValue::Null),
    ]));
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-map")
            .unwrap(),
        val
    );
}

#[test]
fn validate_accepts_deeply_nested_structure() {
    let (mut guard, schema) = setup_guard();
    let inner_map = CanonicalValue::Map(BTreeMap::from([
        ("x".to_string(), CanonicalValue::U64(10)),
        ("y".to_string(), CanonicalValue::Bytes(vec![1, 2, 3])),
    ]));
    let val = CanonicalValue::Array(vec![
        CanonicalValue::Map(BTreeMap::from([(
            "nested".to_string(),
            CanonicalValue::Array(vec![inner_map.clone(), CanonicalValue::Null]),
        )])),
        CanonicalValue::I64(-1),
    ]);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-deep")
            .unwrap(),
        val
    );
}

// ── Validate: rejections ───────────────────────────────────────────────────

#[test]
fn reject_unregistered_class() {
    let (mut guard, schema) = setup_guard();
    let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    let err = guard
        .validate(ObjectDomain::EvidenceRecord, &bytes, "t-unreg")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::SchemaViolation { .. }
    ));
    assert_eq!(err.object_class, ObjectDomain::EvidenceRecord);
    assert_eq!(err.trace_id, "t-unreg");
    // Unregistered class does not bump rejection_count (only emits event).
    assert_eq!(guard.rejection_count(), 0);
}

#[test]
fn reject_trailing_bytes_single() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = make_canonical_payload(&schema, &CanonicalValue::U64(42));
    bytes.push(0x00);
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-trail1")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::TrailingBytes { count: 1 }
    ));
    assert_eq!(guard.rejection_count(), 1);
}

#[test]
fn reject_trailing_bytes_multiple() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-trail4")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::TrailingBytes { count: 4 }
    ));
}

#[test]
fn reject_leading_space() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![b' '];
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-space")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 1 }
    ));
}

#[test]
fn reject_leading_multiple_spaces() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![b' ', b' ', b' '];
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-spaces")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 3 }
    ));
}

#[test]
fn reject_leading_tab() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![b'\t'];
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-tab")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 1 }
    ));
}

#[test]
fn reject_leading_newline() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![b'\n'];
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-newline")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 1 }
    ));
}

#[test]
fn reject_leading_carriage_return() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![b'\r'];
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-cr")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 1 }
    ));
}

#[test]
fn reject_leading_null_bytes() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![0x00, 0x00, 0x00];
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-null-pad")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 3 }
    ));
}

#[test]
fn reject_leading_bom() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-bom")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 3 }
    ));
}

#[test]
fn reject_mixed_leading_padding() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = vec![b' ', b'\t', b'\n', b'\r', 0x00];
    bytes.extend_from_slice(&make_canonical_payload(&schema, &CanonicalValue::Null));
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-mixed-pad")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 5 }
    ));
}

#[test]
fn reject_empty_input() {
    let (mut guard, _schema) = setup_guard();
    let err = guard
        .validate(ObjectDomain::PolicyObject, &[], "t-empty")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::DeserializationFailed { .. }
    ));
}

#[test]
fn reject_invalid_tag() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(schema.as_bytes());
    bytes.push(0xFF); // invalid tag
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-badtag")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::InvalidTag { tag: 0xFF, .. }
    ));
}

#[test]
fn reject_schema_mismatch() {
    let (mut guard, _schema) = setup_guard();
    let wrong_schema = SchemaHash::from_definition(b"wrong-schema-definition");
    let bytes = serialize_with_schema(&wrong_schema, &CanonicalValue::Null);
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-schema-mismatch")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::SchemaViolation { .. }
    ));
}

#[test]
fn reject_non_lexicographic_map_keys() {
    let (mut guard, schema) = setup_guard();
    // Manually construct a map with wrong key order.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(schema.as_bytes()); // 32-byte schema prefix

    const TAG_MAP: u8 = 0x07;
    const TAG_NULL: u8 = 0x08;

    bytes.push(TAG_MAP);
    bytes.extend_from_slice(&2u32.to_be_bytes()); // 2 entries

    // Key "z" first (wrong order).
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'z');
    bytes.push(TAG_NULL);

    // Key "a" second.
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'a');
    bytes.push(TAG_NULL);

    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-nonlex")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::NonLexicographicKeys { .. }
    ));
}

#[test]
fn reject_duplicate_map_keys() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(schema.as_bytes());

    const TAG_MAP: u8 = 0x07;
    const TAG_NULL: u8 = 0x08;

    bytes.push(TAG_MAP);
    bytes.extend_from_slice(&2u32.to_be_bytes()); // 2 entries

    // Key "a" twice.
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'a');
    bytes.push(TAG_NULL);

    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'a');
    bytes.push(TAG_NULL);

    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-dup")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::DuplicateKey { .. }
    ));
}

// ── Cross-class schema enforcement ─────────────────────────────────────────

#[test]
fn cross_class_schema_mismatch() {
    let mut guard = CanonicalGuard::new();
    let s_policy = guard.register_class(ObjectDomain::PolicyObject, "Policy", 1, b"policy-def");
    guard.register_class(ObjectDomain::EvidenceRecord, "Evidence", 1, b"evidence-def");

    // Policy-schema bytes presented to EvidenceRecord class.
    let policy_bytes = make_canonical_payload(&s_policy, &CanonicalValue::U64(1));
    let err = guard
        .validate(ObjectDomain::EvidenceRecord, &policy_bytes, "t-cross")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::SchemaViolation { .. }
    ));
}

#[test]
fn multiple_classes_independent_validation() {
    let mut guard = CanonicalGuard::new();
    let s1 = guard.register_class(ObjectDomain::PolicyObject, "P", 1, b"p-schema");
    let s2 = guard.register_class(ObjectDomain::EvidenceRecord, "E", 1, b"e-schema");
    let s3 = guard.register_class(ObjectDomain::Revocation, "R", 1, b"r-schema");

    let b1 = make_canonical_payload(&s1, &CanonicalValue::U64(1));
    let b2 = make_canonical_payload(&s2, &CanonicalValue::String("test".to_string()));
    let b3 = make_canonical_payload(&s3, &CanonicalValue::Bool(true));

    assert!(
        guard
            .validate(ObjectDomain::PolicyObject, &b1, "t-m1")
            .is_ok()
    );
    assert!(
        guard
            .validate(ObjectDomain::EvidenceRecord, &b2, "t-m2")
            .is_ok()
    );
    assert!(
        guard
            .validate(ObjectDomain::Revocation, &b3, "t-m3")
            .is_ok()
    );

    assert_eq!(guard.acceptance_count(), 3);
    assert_eq!(guard.rejection_count(), 0);
}

// ── Events and counters ────────────────────────────────────────────────────

#[test]
fn event_emitted_on_acceptance() {
    let (mut guard, schema) = setup_guard();
    let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-evt-accept")
        .unwrap();

    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].event_type, GuardEventType::Accepted));
    assert_eq!(events[0].object_class, ObjectDomain::PolicyObject);
    assert_eq!(events[0].trace_id, "t-evt-accept");
    assert_eq!(events[0].input_hash, compute_input_hash(&bytes));
}

#[test]
fn event_emitted_on_rejection() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    bytes.push(0x00);
    guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-evt-reject")
        .unwrap_err();

    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        GuardEventType::Rejected { .. }
    ));
    assert_eq!(events[0].trace_id, "t-evt-reject");
}

#[test]
fn event_emitted_on_unregistered_class() {
    let (mut guard, schema) = setup_guard();
    let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    guard
        .validate(ObjectDomain::EvidenceRecord, &bytes, "t-evt-unreg")
        .unwrap_err();

    let events = guard.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        GuardEventType::UnregisteredClass
    ));
}

#[test]
fn drain_events_clears_buffer() {
    let (mut guard, schema) = setup_guard();
    let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-drain")
        .unwrap();
    assert_eq!(guard.drain_events().len(), 1);
    assert_eq!(guard.drain_events().len(), 0); // second drain is empty
}

#[test]
fn event_counts_aggregation() {
    let (mut guard, schema) = setup_guard();

    // One acceptance.
    let good = make_canonical_payload(&schema, &CanonicalValue::Null);
    guard
        .validate(ObjectDomain::PolicyObject, &good, "t-c1")
        .unwrap();

    // Two rejections (trailing bytes).
    let mut bad1 = good.clone();
    bad1.push(0x00);
    guard
        .validate(ObjectDomain::PolicyObject, &bad1, "t-c2")
        .unwrap_err();

    let mut bad2 = good.clone();
    bad2.push(0xFF);
    guard
        .validate(ObjectDomain::PolicyObject, &bad2, "t-c3")
        .unwrap_err();

    // One unregistered.
    guard
        .validate(ObjectDomain::EvidenceRecord, &good, "t-c4")
        .unwrap_err();

    let counts = guard.event_counts();
    assert_eq!(counts.get("accepted"), Some(&1));
    assert_eq!(counts.get("rejected"), Some(&2));
    assert_eq!(counts.get("unregistered_class"), Some(&1));
}

#[test]
fn acceptance_rejection_counters_are_independent() {
    let (mut guard, schema) = setup_guard();

    for i in 0..5 {
        let good = make_canonical_payload(&schema, &CanonicalValue::U64(i));
        guard
            .validate(ObjectDomain::PolicyObject, &good, "t-cnt")
            .unwrap();
    }

    for _ in 0..3 {
        let mut bad = make_canonical_payload(&schema, &CanonicalValue::Null);
        bad.push(0x00);
        guard
            .validate(ObjectDomain::PolicyObject, &bad, "t-cnt")
            .unwrap_err();
    }

    assert_eq!(guard.acceptance_count(), 5);
    assert_eq!(guard.rejection_count(), 3);
}

// ── Error contains correct input hash ──────────────────────────────────────

#[test]
fn error_input_hash_matches_content_hash() {
    let (mut guard, schema) = setup_guard();
    let mut bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    bytes.push(0x00);
    let expected_hash = compute_input_hash(&bytes);
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-hash")
        .unwrap_err();
    assert_eq!(err.input_hash, expected_hash);
}

#[test]
fn event_input_hash_matches() {
    let (mut guard, schema) = setup_guard();
    let bytes = make_canonical_payload(&schema, &CanonicalValue::U64(77));
    let expected_hash = compute_input_hash(&bytes);
    guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-evt-hash")
        .unwrap();
    let events = guard.drain_events();
    assert_eq!(events[0].input_hash, expected_hash);
}

// ── is_canonical_raw (standalone) ──────────────────────────────────────────

#[test]
fn is_canonical_raw_accepts_all_value_types() {
    let values = vec![
        CanonicalValue::U64(0),
        CanonicalValue::U64(u64::MAX),
        CanonicalValue::I64(i64::MIN),
        CanonicalValue::I64(0),
        CanonicalValue::Bool(true),
        CanonicalValue::Bool(false),
        CanonicalValue::Bytes(vec![]),
        CanonicalValue::Bytes(vec![0xFF; 100]),
        CanonicalValue::String(String::new()),
        CanonicalValue::String("test".to_string()),
        CanonicalValue::Array(vec![]),
        CanonicalValue::Array(vec![CanonicalValue::Null, CanonicalValue::U64(1)]),
        CanonicalValue::Map(BTreeMap::new()),
        CanonicalValue::Map(BTreeMap::from([(
            "k".to_string(),
            CanonicalValue::Bool(true),
        )])),
        CanonicalValue::Null,
    ];

    for val in &values {
        let bytes = encode_value(val);
        assert!(
            CanonicalGuard::is_canonical_raw(&bytes).is_ok(),
            "failed for: {val:?}"
        );
    }
}

#[test]
fn is_canonical_raw_rejects_trailing_bytes() {
    let mut bytes = encode_value(&CanonicalValue::U64(42));
    bytes.push(0xFF);
    let err = CanonicalGuard::is_canonical_raw(&bytes).unwrap_err();
    assert!(matches!(err, CanonicalViolation::TrailingBytes { .. }));
}

#[test]
fn is_canonical_raw_rejects_leading_space() {
    let encoded = encode_value(&CanonicalValue::U64(42));
    let mut bytes = vec![b' '];
    bytes.extend_from_slice(&encoded);
    let err = CanonicalGuard::is_canonical_raw(&bytes).unwrap_err();
    assert!(matches!(err, CanonicalViolation::LeadingPadding { .. }));
}

#[test]
fn is_canonical_raw_rejects_leading_bom() {
    let encoded = encode_value(&CanonicalValue::Null);
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(&encoded);
    let err = CanonicalGuard::is_canonical_raw(&bytes).unwrap_err();
    assert!(matches!(
        err,
        CanonicalViolation::LeadingPadding { byte_count: 3 }
    ));
}

#[test]
fn is_canonical_raw_empty_input() {
    // Empty bytes: decode should fail with a deserialization error.
    let err = CanonicalGuard::is_canonical_raw(&[]).unwrap_err();
    assert!(matches!(
        err,
        CanonicalViolation::DeserializationFailed { .. }
    ));
}

// ── validate_from_registry ─────────────────────────────────────────────────

#[test]
fn validate_from_registry_finds_class() {
    let mut guard = CanonicalGuard::new();
    let schema = guard.register_class(
        ObjectDomain::Revocation,
        "Revocation",
        1,
        b"revocation-schema",
    );
    let bytes = make_canonical_payload(&schema, &CanonicalValue::Bool(false));
    let (domain, value) = guard.validate_from_registry(&bytes, "t-reg-1").unwrap();
    assert_eq!(domain, ObjectDomain::Revocation);
    assert_eq!(value, CanonicalValue::Bool(false));
}

#[test]
fn validate_from_registry_rejects_unknown_schema() {
    let mut guard = CanonicalGuard::new();
    let unknown_schema = SchemaHash::from_definition(b"totally-unknown");
    let bytes = make_canonical_payload(&unknown_schema, &CanonicalValue::Null);
    let err = guard
        .validate_from_registry(&bytes, "t-reg-unknown")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::SchemaViolation { .. }
    ));
}

#[test]
fn validate_from_registry_rejects_too_short_input() {
    let mut guard = CanonicalGuard::new();
    // Less than 32 bytes.
    let short = vec![0u8; 10];
    let err = guard
        .validate_from_registry(&short, "t-reg-short")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::DeserializationFailed { .. }
    ));
}

#[test]
fn validate_from_registry_with_multiple_classes() {
    let mut guard = CanonicalGuard::new();
    let s1 = guard.register_class(ObjectDomain::PolicyObject, "P", 1, b"p-def");
    let s2 = guard.register_class(ObjectDomain::EvidenceRecord, "E", 1, b"e-def");

    let b1 = make_canonical_payload(&s1, &CanonicalValue::U64(1));
    let b2 = make_canonical_payload(&s2, &CanonicalValue::String("ev".to_string()));

    let (d1, v1) = guard.validate_from_registry(&b1, "t-mr1").unwrap();
    assert_eq!(d1, ObjectDomain::PolicyObject);
    assert_eq!(v1, CanonicalValue::U64(1));

    let (d2, v2) = guard.validate_from_registry(&b2, "t-mr2").unwrap();
    assert_eq!(d2, ObjectDomain::EvidenceRecord);
    assert_eq!(v2, CanonicalValue::String("ev".to_string()));
}

// ── CanonicalityCheck trait ────────────────────────────────────────────────

#[test]
fn canonicality_check_trait_domain() {
    let guard = CanonicalGuard::new();
    assert_eq!(guard.domain(), ObjectDomain::PolicyObject);
}

#[test]
fn canonicality_check_trait_accepts_valid() {
    let guard = CanonicalGuard::new();
    let val = CanonicalValue::U64(42);
    let bytes = encode_value(&val);
    assert!(guard.check_canonical(&bytes, "t-trait-ok").is_ok());
}

#[test]
fn canonicality_check_trait_rejects_leading_padding() {
    let guard = CanonicalGuard::new();
    let encoded = encode_value(&CanonicalValue::U64(42));
    let mut bytes = vec![b' '];
    bytes.extend_from_slice(&encoded);
    let err = guard.check_canonical(&bytes, "t-trait-pad").unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::LeadingPadding { byte_count: 1 }
    ));
    assert_eq!(err.trace_id, "t-trait-pad");
    assert_eq!(err.object_class, ObjectDomain::PolicyObject);
}

#[test]
fn canonicality_check_trait_rejects_trailing_bytes() {
    let guard = CanonicalGuard::new();
    let mut bytes = encode_value(&CanonicalValue::U64(42));
    bytes.push(0xFF);
    let err = guard.check_canonical(&bytes, "t-trait-trail").unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::TrailingBytes { .. }
    ));
}

#[test]
fn canonicality_check_trait_rejects_invalid() {
    let guard = CanonicalGuard::new();
    let bytes = vec![0xFF]; // invalid tag
    let err = guard.check_canonical(&bytes, "t-trait-bad").unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::InvalidTag { tag: 0xFF, .. }
            | CanonicalViolation::DeserializationFailed { .. }
    ));
}

#[test]
fn canonicality_check_trait_returns_input_hash() {
    let guard = CanonicalGuard::new();
    let bytes = vec![b' ', 0x01];
    let expected_hash = compute_input_hash(&bytes);
    let err = guard.check_canonical(&bytes, "t-trait-hash").unwrap_err();
    assert_eq!(err.input_hash, expected_hash);
}

// ── Serde round-trips ──────────────────────────────────────────────────────

#[test]
fn canonical_violation_serde_round_trip_all_variants() {
    let violations = vec![
        CanonicalViolation::NonLexicographicKeys {
            prev_key: "z".to_string(),
            current_key: "a".to_string(),
        },
        CanonicalViolation::DuplicateKey {
            key: "k".to_string(),
        },
        CanonicalViolation::TrailingBytes { count: 42 },
        CanonicalViolation::LeadingPadding { byte_count: 3 },
        CanonicalViolation::RoundTripMismatch {
            first_diff_offset: 5,
            expected: 0x01,
            actual: 0x02,
        },
        CanonicalViolation::LengthMismatch {
            input_len: 100,
            canonical_len: 99,
        },
        CanonicalViolation::DeserializationFailed {
            detail: "bad data".to_string(),
        },
        CanonicalViolation::InvalidTag {
            tag: 0xFF,
            offset: 0,
        },
        CanonicalViolation::SchemaViolation {
            detail: "mismatch".to_string(),
        },
    ];
    for v in &violations {
        let json = serde_json::to_string(v).expect("serialize");
        let restored: CanonicalViolation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*v, restored, "failed for: {v:?}");
    }
}

#[test]
fn non_canonical_error_serde_round_trip() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::EvidenceRecord,
        input_hash: [0xAB; 32],
        violation: CanonicalViolation::TrailingBytes { count: 1 },
        trace_id: "t-serde-err".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let restored: NonCanonicalError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, restored);
}

#[test]
fn guard_event_serde_round_trip() {
    let event = GuardEvent {
        event_type: GuardEventType::Rejected {
            violation: CanonicalViolation::InvalidTag {
                tag: 0xFE,
                offset: 32,
            },
        },
        object_class: ObjectDomain::Revocation,
        trace_id: "t-ser".to_string(),
        input_hash: [0x01; 32],
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: GuardEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn guard_event_type_serde_round_trip_all_variants() {
    let variants = vec![
        GuardEventType::Accepted,
        GuardEventType::Rejected {
            violation: CanonicalViolation::DuplicateKey {
                key: "k".to_string(),
            },
        },
        GuardEventType::UnregisteredClass,
    ];
    for evt in &variants {
        let json = serde_json::to_string(evt).expect("serialize");
        let restored: GuardEventType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*evt, restored);
    }
}

// ── Deterministic behavior ─────────────────────────────────────────────────

#[test]
fn deterministic_same_input_same_output() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Map(BTreeMap::from([
        ("alpha".to_string(), CanonicalValue::U64(1)),
        ("beta".to_string(), CanonicalValue::Bool(true)),
        ("gamma".to_string(), CanonicalValue::Null),
    ]));
    let bytes = make_canonical_payload(&schema, &val);

    // Validate twice and confirm identical results.
    let r1 = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-det1")
        .unwrap();
    let r2 = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-det2")
        .unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn deterministic_re_serialization_is_idempotent() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Array(vec![
        CanonicalValue::I64(-1),
        CanonicalValue::Map(BTreeMap::from([
            ("a".to_string(), CanonicalValue::U64(0)),
            ("b".to_string(), CanonicalValue::Bytes(vec![1, 2, 3])),
        ])),
    ]);
    let bytes1 = make_canonical_payload(&schema, &val);
    let decoded = guard
        .validate(ObjectDomain::PolicyObject, &bytes1, "t-idem")
        .unwrap();
    let bytes2 = make_canonical_payload(&schema, &decoded);
    assert_eq!(bytes1, bytes2);
}

#[test]
fn round_trip_stability_all_types() {
    let (mut guard, schema) = setup_guard();
    let values = vec![
        CanonicalValue::U64(0),
        CanonicalValue::U64(u64::MAX),
        CanonicalValue::I64(-1),
        CanonicalValue::I64(i64::MIN),
        CanonicalValue::I64(i64::MAX),
        CanonicalValue::Bool(true),
        CanonicalValue::Bool(false),
        CanonicalValue::Bytes(vec![]),
        CanonicalValue::Bytes(vec![0xFF; 256]),
        CanonicalValue::String(String::new()),
        CanonicalValue::String("unicode: \u{1F600}".to_string()),
        CanonicalValue::Array(vec![]),
        CanonicalValue::Map(BTreeMap::new()),
        CanonicalValue::Null,
    ];

    for val in &values {
        let bytes = make_canonical_payload(&schema, val);
        let result = guard.validate(ObjectDomain::PolicyObject, &bytes, "t-round");
        assert!(result.is_ok(), "failed for value: {val:?}");
        let decoded = result.unwrap();
        assert_eq!(&decoded, val);
        let re_serialized = make_canonical_payload(&schema, &decoded);
        assert_eq!(bytes, re_serialized, "re-serialization mismatch: {val:?}");
    }
}

// ── Edge cases ─────────────────────────────────────────────────────────────

#[test]
fn large_byte_payload_accepted() {
    let (mut guard, schema) = setup_guard();
    let val = CanonicalValue::Bytes(vec![0xAB; 10_000]);
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-large")
            .unwrap(),
        val
    );
}

#[test]
fn deeply_nested_arrays_accepted() {
    let (mut guard, schema) = setup_guard();
    let mut val = CanonicalValue::U64(0);
    for _ in 0..20 {
        val = CanonicalValue::Array(vec![val]);
    }
    let bytes = make_canonical_payload(&schema, &val);
    assert_eq!(
        guard
            .validate(ObjectDomain::PolicyObject, &bytes, "t-deepnest")
            .unwrap(),
        val
    );
}

#[test]
fn map_with_many_keys_accepted() {
    let (mut guard, schema) = setup_guard();
    let mut map = BTreeMap::new();
    for i in 0..100 {
        map.insert(format!("key_{i:04}"), CanonicalValue::U64(i));
    }
    let val = CanonicalValue::Map(map);
    let bytes = make_canonical_payload(&schema, &val);
    let decoded = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-bigmap")
        .unwrap();
    assert_eq!(decoded, val);
}

#[test]
fn only_schema_prefix_no_value() {
    let (mut guard, schema) = setup_guard();
    // Just the 32-byte schema prefix with no value after it.
    let bytes = schema.as_bytes().to_vec();
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bytes, "t-no-value")
        .unwrap_err();
    // Should fail during deserialization (buffer too short for value).
    assert!(matches!(
        err.violation,
        CanonicalViolation::DeserializationFailed { .. }
    ));
}

#[test]
fn truncated_value_after_schema_prefix() {
    let (mut guard, schema) = setup_guard();
    let full = make_canonical_payload(&schema, &CanonicalValue::String("hello".to_string()));
    // Truncate: keep schema prefix + partial value.
    let truncated = full[..34].to_vec();
    let err = guard
        .validate(ObjectDomain::PolicyObject, &truncated, "t-truncated")
        .unwrap_err();
    assert!(
        matches!(
            err.violation,
            CanonicalViolation::DeserializationFailed { .. }
                | CanonicalViolation::LengthMismatch { .. }
                | CanonicalViolation::RoundTripMismatch { .. }
        ),
        "got: {:?}",
        err.violation
    );
}

#[test]
fn register_all_domain_classes() {
    let mut guard = CanonicalGuard::new();
    let domains = [
        ObjectDomain::PolicyObject,
        ObjectDomain::EvidenceRecord,
        ObjectDomain::Revocation,
        ObjectDomain::SignedManifest,
        ObjectDomain::Attestation,
        ObjectDomain::CapabilityToken,
        ObjectDomain::CheckpointArtifact,
        ObjectDomain::RecoveryArtifact,
        ObjectDomain::KeyBundle,
    ];
    for (i, domain) in domains.iter().enumerate() {
        guard.register_class(
            *domain,
            &format!("Schema{i}"),
            1,
            format!("def-{i}").as_bytes(),
        );
    }
    assert_eq!(guard.registered_class_count(), domains.len());
    for domain in &domains {
        assert!(guard.is_class_registered(domain));
    }
}

#[test]
fn sequential_accepts_and_rejects_interleaved() {
    let (mut guard, schema) = setup_guard();

    // Interleave accepts and rejects.
    for i in 0u64..10 {
        let good = make_canonical_payload(&schema, &CanonicalValue::U64(i));
        guard
            .validate(ObjectDomain::PolicyObject, &good, &format!("accept-{i}"))
            .unwrap();

        let mut bad = make_canonical_payload(&schema, &CanonicalValue::U64(i));
        bad.push(0x00);
        guard
            .validate(ObjectDomain::PolicyObject, &bad, &format!("reject-{i}"))
            .unwrap_err();
    }

    assert_eq!(guard.acceptance_count(), 10);
    assert_eq!(guard.rejection_count(), 10);

    let events = guard.drain_events();
    assert_eq!(events.len(), 20);

    // Verify alternating pattern.
    for (idx, event) in events.iter().enumerate() {
        if idx.is_multiple_of(2) {
            assert!(matches!(event.event_type, GuardEventType::Accepted));
        } else {
            assert!(matches!(event.event_type, GuardEventType::Rejected { .. }));
        }
    }
}

#[test]
fn trace_id_preserved_in_all_error_paths() {
    let (mut guard, schema) = setup_guard();

    // Unregistered class error.
    let bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    let err = guard
        .validate(ObjectDomain::EvidenceRecord, &bytes, "trace-unreg")
        .unwrap_err();
    assert_eq!(err.trace_id, "trace-unreg");

    // Leading padding error.
    let mut padded = vec![b' '];
    padded.extend_from_slice(&bytes);
    let err = guard
        .validate(ObjectDomain::PolicyObject, &padded, "trace-pad")
        .unwrap_err();
    assert_eq!(err.trace_id, "trace-pad");

    // Trailing bytes error.
    let mut trailed = bytes.clone();
    trailed.push(0xFF);
    let err = guard
        .validate(ObjectDomain::PolicyObject, &trailed, "trace-trail")
        .unwrap_err();
    assert_eq!(err.trace_id, "trace-trail");

    // Invalid tag error.
    let mut bad_tag = Vec::new();
    bad_tag.extend_from_slice(schema.as_bytes());
    bad_tag.push(0xFF);
    let err = guard
        .validate(ObjectDomain::PolicyObject, &bad_tag, "trace-tag")
        .unwrap_err();
    assert_eq!(err.trace_id, "trace-tag");
}

#[test]
fn schema_hash_deterministic_from_same_definition() {
    let mut g1 = CanonicalGuard::new();
    let mut g2 = CanonicalGuard::new();
    let s1 = g1.register_class(ObjectDomain::PolicyObject, "P", 1, b"identical-def");
    let s2 = g2.register_class(ObjectDomain::PolicyObject, "P", 1, b"identical-def");
    assert_eq!(s1, s2);
}

#[test]
fn schema_hash_differs_for_different_definitions() {
    let mut g = CanonicalGuard::new();
    let s1 = g.register_class(ObjectDomain::PolicyObject, "P", 1, b"def-aaa");
    let s2 = g.register_class(ObjectDomain::PolicyObject, "P", 1, b"def-bbb");
    assert_ne!(s1, s2);
}

// ── Clone / Eq on violation types ──────────────────────────────────────────

#[test]
fn canonical_violation_clone_eq() {
    let v = CanonicalViolation::RoundTripMismatch {
        first_diff_offset: 10,
        expected: 0x41,
        actual: 0x42,
    };
    let v2 = v.clone();
    assert_eq!(v, v2);
}

#[test]
fn non_canonical_error_clone_eq() {
    let err = NonCanonicalError {
        object_class: ObjectDomain::PolicyObject,
        input_hash: [0x55; 32],
        violation: CanonicalViolation::LeadingPadding { byte_count: 1 },
        trace_id: "t-clone".to_string(),
    };
    let err2 = err.clone();
    assert_eq!(err, err2);
}

#[test]
fn guard_event_clone_eq() {
    let evt = GuardEvent {
        event_type: GuardEventType::Accepted,
        object_class: ObjectDomain::Revocation,
        trace_id: "t-cln".to_string(),
        input_hash: [0xCC; 32],
    };
    let evt2 = evt.clone();
    assert_eq!(evt, evt2);
}

#[test]
fn guard_event_type_clone_eq() {
    let t1 = GuardEventType::Accepted;
    assert_eq!(t1.clone(), t1);

    let t2 = GuardEventType::Rejected {
        violation: CanonicalViolation::TrailingBytes { count: 1 },
    };
    assert_eq!(t2.clone(), t2);

    let t3 = GuardEventType::UnregisteredClass;
    assert_eq!(t3.clone(), t3);
}

// ── Violation inequality ───────────────────────────────────────────────────

#[test]
fn different_violations_are_not_equal() {
    let v1 = CanonicalViolation::TrailingBytes { count: 1 };
    let v2 = CanonicalViolation::TrailingBytes { count: 2 };
    let v3 = CanonicalViolation::DuplicateKey {
        key: "x".to_string(),
    };
    assert_ne!(v1, v2);
    assert_ne!(v1, v3);
}

// ── Validate from registry also checks canonicality ────────────────────────

#[test]
fn validate_from_registry_rejects_trailing_bytes() {
    let mut guard = CanonicalGuard::new();
    let schema = guard.register_class(ObjectDomain::PolicyObject, "P", 1, b"p-def");
    let mut bytes = make_canonical_payload(&schema, &CanonicalValue::Null);
    bytes.push(0xAA);
    let err = guard
        .validate_from_registry(&bytes, "t-vfr-trail")
        .unwrap_err();
    assert!(matches!(
        err.violation,
        CanonicalViolation::TrailingBytes { .. }
    ));
}

#[test]
fn validate_from_registry_rejects_leading_padding() {
    let mut guard = CanonicalGuard::new();
    let schema = guard.register_class(ObjectDomain::PolicyObject, "P", 1, b"p-def");
    let payload = make_canonical_payload(&schema, &CanonicalValue::Null);
    let mut bytes = vec![b' '];
    bytes.extend_from_slice(&payload);
    // Leading padding shifts the schema prefix, so validate_from_registry
    // sees an unrecognized schema hash and returns SchemaViolation (the
    // leading-padding check only runs inside validate() after class lookup).
    let err = guard
        .validate_from_registry(&bytes, "t-vfr-pad")
        .unwrap_err();
    assert!(
        matches!(
            err.violation,
            CanonicalViolation::SchemaViolation { .. } | CanonicalViolation::LeadingPadding { .. }
        ),
        "unexpected violation: {:?}",
        err.violation
    );
}

// ── Guard Debug impl ──────────────────────────────────────────────────────

#[test]
fn guard_is_debug() {
    let guard = CanonicalGuard::new();
    let debug_str = format!("{guard:?}");
    assert!(debug_str.contains("CanonicalGuard"), "got: {debug_str}");
}
