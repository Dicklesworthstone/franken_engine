//! Enrichment integration tests for the `remote_computation_registry` module.
//!
//! Covers additional edge cases, event tracking, determinism, serde, and
//! cross-cutting interactions beyond the base integration test suite.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;

use frankenengine_engine::capability::{CapabilityProfile, ProfileKind};
use frankenengine_engine::control_plane::SchemaVersion;
use frankenengine_engine::deterministic_serde::CanonicalValue;
use frankenengine_engine::remote_computation_registry::{
    ComputationName, ComputationRegistration, ComputationSchema, IdempotencyClass, RegistryError,
    RegistryEvent, RemoteComputationRegistry, SchemaVersionExt, VersionNegotiationResult,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_schema(desc: &str, def: &[u8], fields: Vec<&str>) -> ComputationSchema {
    ComputationSchema::new(desc, def, fields.into_iter().map(String::from).collect())
}

fn make_registration(
    name: &str,
    kind: ProfileKind,
    class: IdempotencyClass,
) -> ComputationRegistration {
    ComputationRegistration {
        name: ComputationName::new(name).unwrap(),
        input_schema: make_schema("in", b"in-schema", vec!["field_a", "field_b"]),
        output_schema: make_schema("out", b"out-schema", vec!["status"]),
        version: SchemaVersion::new(1, 0, 0),
        capability_required: kind,
        idempotency_class: class,
    }
}

fn default_reg(name: &str) -> ComputationRegistration {
    make_registration(name, ProfileKind::Remote, IdempotencyClass::RequiresKey)
}

fn valid_input() -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "field_a".to_string(),
        CanonicalValue::String("alpha".to_string()),
    );
    map.insert(
        "field_b".to_string(),
        CanonicalValue::String("beta".to_string()),
    );
    CanonicalValue::Map(map)
}

// ---------------------------------------------------------------------------
// ComputationName edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_name_single_char_valid() {
    let name = ComputationName::new("a").unwrap();
    assert_eq!(name.as_str(), "a");
}

#[test]
fn enrich_name_all_digits_valid() {
    let name = ComputationName::new("123").unwrap();
    assert_eq!(name.as_str(), "123");
}

#[test]
fn enrich_name_dots_only_valid() {
    let name = ComputationName::new("...").unwrap();
    assert_eq!(name.as_str(), "...");
}

#[test]
fn enrich_name_underscores_only_valid() {
    let name = ComputationName::new("___").unwrap();
    assert_eq!(name.as_str(), "___");
}

#[test]
fn enrich_name_hyphen_rejected() {
    assert!(ComputationName::new("foo-bar").is_err());
}

#[test]
fn enrich_name_at_sign_rejected() {
    assert!(ComputationName::new("foo@bar").is_err());
}

#[test]
fn enrich_name_unicode_rejected() {
    assert!(ComputationName::new("caf\u{00e9}").is_err());
}

#[test]
fn enrich_name_clone_equality() {
    let a = ComputationName::new("test").unwrap();
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.as_str(), b.as_str());
}

#[test]
fn enrich_name_ordering() {
    let a = ComputationName::new("aaa").unwrap();
    let b = ComputationName::new("bbb").unwrap();
    assert!(a < b);
}

// ---------------------------------------------------------------------------
// SchemaVersion compatibility edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_version_zero_zero_compatible() {
    let v = SchemaVersion::new(0, 0, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(0, 0, 0)));
}

#[test]
fn enrich_version_zero_minor_bump_compat() {
    let v = SchemaVersion::new(0, 0, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(0, 5, 0)));
}

#[test]
fn enrich_version_patch_ignored_in_compat() {
    let v = SchemaVersion::new(1, 0, 0);
    // patch is ignored in compatibility check
    assert!(v.is_compatible_with(&SchemaVersion::new(1, 0, 99)));
}

// ---------------------------------------------------------------------------
// Registry: multiple registrations and ordering
// ---------------------------------------------------------------------------

#[test]
fn enrich_registry_ten_registrations() {
    let mut reg = RemoteComputationRegistry::new();
    for i in 0..10 {
        reg.register(default_reg(&format!("comp_{i:02}"))).unwrap();
    }
    assert_eq!(reg.len(), 10);
    let names = reg.computation_names();
    // BTreeMap order: comp_00, comp_01, ... comp_09
    for (i, name) in names.iter().enumerate().take(10) {
        assert_eq!(*name, format!("comp_{i:02}"));
    }
}

#[test]
fn enrich_registry_default_is_empty() {
    let reg = RemoteComputationRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn enrich_registry_new_equals_default() {
    let a = RemoteComputationRegistry::new();
    let b = RemoteComputationRegistry::default();
    assert_eq!(a.len(), b.len());
    assert!(a.is_empty());
    assert!(b.is_empty());
}

// ---------------------------------------------------------------------------
// Hot registration: profile coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_hot_register_with_full_profile() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::full();
    reg.hot_register(default_reg("hot_full"), &profile, "t-f")
        .unwrap();
    assert_eq!(reg.len(), 1);
}

#[test]
fn enrich_hot_register_with_engine_core_denied() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::engine_core();
    // engine_core lacks EvidenceEmit, so hot-registration is denied
    let err = reg
        .hot_register(default_reg("hot_ec"), &profile, "t-ec")
        .unwrap_err();
    assert!(matches!(err, RegistryError::HotRegistrationDenied { .. }));
}

#[test]
fn enrich_hot_register_denied_event_in_audit() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::compute_only();
    let _ = reg.hot_register(default_reg("denied"), &profile, "t-denied");
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "hot_registration_denied");
    assert_eq!(events[0].outcome, "denied");
}

// ---------------------------------------------------------------------------
// Schema validation: CanonicalValue variants
// ---------------------------------------------------------------------------

#[test]
fn enrich_validate_input_null_rejected() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("comp")).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let err = reg
        .validate_input(&name, &CanonicalValue::Null, "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrich_validate_input_u64_rejected() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("comp")).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let err = reg
        .validate_input(&name, &CanonicalValue::U64(42), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrich_validate_input_bool_rejected() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("comp")).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let err = reg
        .validate_input(&name, &CanonicalValue::Bool(true), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrich_validate_input_empty_map_missing_fields() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("comp")).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let input = CanonicalValue::Map(BTreeMap::new());
    let err = reg.validate_input(&name, &input, "t").unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrich_validate_input_hash_32_bytes() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("comp")).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let hash = reg.validate_input(&name, &valid_input(), "t").unwrap();
    assert_eq!(hash.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// Deterministic input hashing: domain separation
// ---------------------------------------------------------------------------

#[test]
fn enrich_compute_input_hash_domain_separation() {
    let name_a = ComputationName::new("domain_a").unwrap();
    let name_b = ComputationName::new("domain_b").unwrap();
    let input = CanonicalValue::Map(BTreeMap::new());
    let h1 = RemoteComputationRegistry::compute_input_hash(&name_a, &input);
    let h2 = RemoteComputationRegistry::compute_input_hash(&name_b, &input);
    assert_ne!(h1, h2);
}

#[test]
fn enrich_compute_input_hash_empty_map_deterministic() {
    let name = ComputationName::new("x").unwrap();
    let input = CanonicalValue::Map(BTreeMap::new());
    let h1 = RemoteComputationRegistry::compute_input_hash(&name, &input);
    let h2 = RemoteComputationRegistry::compute_input_hash(&name, &input);
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// Capability enforcement: all profile kinds
// ---------------------------------------------------------------------------

#[test]
fn enrich_capability_check_compute_only_registration() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = default_reg("co_comp");
    comp.capability_required = ProfileKind::ComputeOnly;
    reg.register(comp).unwrap();
    let name = ComputationName::new("co_comp").unwrap();
    // compute_only profile should pass for ComputeOnly requirement
    assert!(
        reg.check_capability(&name, &CapabilityProfile::compute_only(), "t")
            .is_ok()
    );
}

#[test]
fn enrich_capability_check_full_always_passes() {
    let mut reg = RemoteComputationRegistry::new();
    let kinds = [
        (ProfileKind::Remote, "comp_remote"),
        (ProfileKind::ComputeOnly, "comp_compute_only"),
        (ProfileKind::EngineCore, "comp_engine_core"),
        (ProfileKind::Policy, "comp_policy"),
        (ProfileKind::Full, "comp_full"),
    ];
    for (kind, name_str) in kinds {
        let mut comp = default_reg(name_str);
        comp.capability_required = kind;
        reg.register(comp).unwrap();
        let name = ComputationName::new(name_str).unwrap();
        assert!(
            reg.check_capability(&name, &CapabilityProfile::full(), "t")
                .is_ok()
        );
    }
}

// ---------------------------------------------------------------------------
// Version negotiation: edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_negotiate_same_version_compatible() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = default_reg("comp");
    comp.version = SchemaVersion::new(3, 5, 2);
    reg.register(comp).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(3, 5, 2))
        .unwrap();
    assert!(result.compatible);
}

#[test]
fn enrich_negotiate_higher_minor_compatible() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = default_reg("comp");
    comp.version = SchemaVersion::new(2, 3, 0);
    reg.register(comp).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(2, 10, 0))
        .unwrap();
    assert!(result.compatible);
}

#[test]
fn enrich_negotiate_lower_minor_incompatible() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = default_reg("comp");
    comp.version = SchemaVersion::new(2, 5, 0);
    reg.register(comp).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(2, 4, 0))
        .unwrap();
    assert!(!result.compatible);
}

#[test]
fn enrich_negotiate_version_result_fields() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = default_reg("comp");
    comp.version = SchemaVersion::new(1, 2, 3);
    reg.register(comp).unwrap();
    let name = ComputationName::new("comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(1, 5, 0))
        .unwrap();
    assert_eq!(result.computation_name.as_str(), "comp");
    assert_eq!(result.local_version, SchemaVersion::new(1, 2, 3));
    assert_eq!(result.remote_version, SchemaVersion::new(1, 5, 0));
}

// ---------------------------------------------------------------------------
// Closure rejection
// ---------------------------------------------------------------------------

#[test]
fn enrich_closure_rejection_error_display() {
    let err = RemoteComputationRegistry::reject_closure("test rejection");
    let msg = err.to_string();
    assert!(msg.contains("test rejection"));
    assert!(msg.contains("closure"));
}

// ---------------------------------------------------------------------------
// Event accumulation patterns
// ---------------------------------------------------------------------------

#[test]
fn enrich_events_accumulate_across_operations() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("c1")).unwrap();
    reg.register(default_reg("c2")).unwrap();
    let name = ComputationName::new("c1").unwrap();
    reg.validate_input(&name, &valid_input(), "t1").unwrap();
    reg.validate_input(&name, &valid_input(), "t2").unwrap();
    let events = reg.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].trace_id, "t1");
    assert_eq!(events[1].trace_id, "t2");
}

#[test]
fn enrich_event_counts_persist_after_drain() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("comp")).unwrap();
    let name = ComputationName::new("comp").unwrap();
    reg.validate_input(&name, &valid_input(), "t1").unwrap();
    let _ = reg.drain_events();
    // Event counts should persist after draining events
    assert_eq!(reg.event_counts().get("validation_success"), Some(&1));
}

#[test]
fn enrich_registration_event_count() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(default_reg("a")).unwrap();
    reg.register(default_reg("b")).unwrap();
    reg.register(default_reg("c")).unwrap();
    assert_eq!(reg.event_counts().get("registration"), Some(&3));
}

// ---------------------------------------------------------------------------
// RegistryError display coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_error_display_duplicate_registration() {
    let err = RegistryError::DuplicateRegistration {
        name: "dup".to_string(),
    };
    assert!(err.to_string().contains("dup"));
    assert!(err.to_string().contains("already registered"));
}

#[test]
fn enrich_error_display_computation_not_found() {
    let err = RegistryError::ComputationNotFound {
        name: "missing".to_string(),
    };
    assert!(err.to_string().contains("missing"));
    assert!(err.to_string().contains("not found"));
}

#[test]
fn enrich_error_display_schema_validation_failed() {
    let err = RegistryError::SchemaValidationFailed {
        computation_name: "comp".to_string(),
        reason: "bad field".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("comp"));
    assert!(msg.contains("bad field"));
}

#[test]
fn enrich_error_display_capability_denied() {
    let err = RegistryError::CapabilityDenied {
        computation_name: "comp".to_string(),
        required: ProfileKind::Full,
        held: ProfileKind::ComputeOnly,
    };
    let msg = err.to_string();
    assert!(msg.contains("comp"));
    assert!(msg.contains("denied"));
}

#[test]
fn enrich_error_display_version_incompatible() {
    let err = RegistryError::VersionIncompatible {
        computation_name: "comp".to_string(),
        registered: SchemaVersion::new(1, 0, 0),
        requested: SchemaVersion::new(2, 0, 0),
    };
    let msg = err.to_string();
    assert!(msg.contains("incompatible"));
}

#[test]
fn enrich_error_display_hot_registration_denied() {
    let err = RegistryError::HotRegistrationDenied {
        reason: "no caps".to_string(),
    };
    assert!(err.to_string().contains("no caps"));
}

// ---------------------------------------------------------------------------
// Serde round-trips for all error variants
// ---------------------------------------------------------------------------

#[test]
fn enrich_serde_registry_error_all_variants() {
    let errors: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName {
            name: "BAD".to_string(),
            reason: "upper".to_string(),
        },
        RegistryError::DuplicateRegistration {
            name: "dup".to_string(),
        },
        RegistryError::ComputationNotFound {
            name: "missing".to_string(),
        },
        RegistryError::SchemaValidationFailed {
            computation_name: "c".to_string(),
            reason: "r".to_string(),
        },
        RegistryError::CapabilityDenied {
            computation_name: "c".to_string(),
            required: ProfileKind::Full,
            held: ProfileKind::ComputeOnly,
        },
        RegistryError::VersionIncompatible {
            computation_name: "c".to_string(),
            registered: SchemaVersion::new(1, 0, 0),
            requested: SchemaVersion::new(2, 0, 0),
        },
        RegistryError::ClosureRejected {
            reason: "closure".to_string(),
        },
        RegistryError::HotRegistrationDenied {
            reason: "denied".to_string(),
        },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let back: RegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

#[test]
fn enrich_serde_registry_event_roundtrip() {
    let event = RegistryEvent {
        trace_id: "trace-1".to_string(),
        component: "registry".to_string(),
        computation_name: "comp".to_string(),
        version: "1.0.0".to_string(),
        input_hash: "abc123".to_string(),
        event: "validation".to_string(),
        outcome: "success".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RegistryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrich_serde_version_negotiation_result_roundtrip() {
    let result = VersionNegotiationResult {
        computation_name: ComputationName::new("comp").unwrap(),
        compatible: true,
        local_version: SchemaVersion::new(1, 0, 0),
        remote_version: SchemaVersion::new(1, 2, 0),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Idempotency class coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_naturally_idempotent_registration() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = default_reg("read_only");
    comp.idempotency_class = IdempotencyClass::NaturallyIdempotent;
    reg.register(comp).unwrap();
    let name = ComputationName::new("read_only").unwrap();
    let found = reg.lookup(&name).unwrap();
    assert_eq!(
        found.idempotency_class,
        IdempotencyClass::NaturallyIdempotent
    );
}

#[test]
fn enrich_idempotency_class_ord() {
    assert!(IdempotencyClass::NaturallyIdempotent < IdempotencyClass::RequiresKey);
}

// ---------------------------------------------------------------------------
// ComputationSchema hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrich_schema_hash_deterministic() {
    let s1 = make_schema("d", b"def", vec!["x"]);
    let s2 = make_schema("d", b"def", vec!["x"]);
    assert_eq!(s1.schema_hash, s2.schema_hash);
}

#[test]
fn enrich_schema_hash_differs_on_different_definition() {
    let s1 = make_schema("d", b"def-a", vec!["x"]);
    let s2 = make_schema("d", b"def-b", vec!["x"]);
    assert_ne!(s1.schema_hash, s2.schema_hash);
}
