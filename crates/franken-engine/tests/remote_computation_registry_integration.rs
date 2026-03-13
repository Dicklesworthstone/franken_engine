//! Integration tests for the `remote_computation_registry` module.
//!
//! Tests named remote computation registry: registration, validation,
//! capability enforcement, version negotiation, idempotency, events, serde.

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

fn test_input_schema() -> ComputationSchema {
    ComputationSchema::new(
        "test input schema",
        b"test-input-schema-def-v1",
        vec!["action".to_string(), "target".to_string()],
    )
}

fn test_output_schema() -> ComputationSchema {
    ComputationSchema::new(
        "test output schema",
        b"test-output-schema-def-v1",
        vec!["status".to_string(), "result".to_string()],
    )
}

fn test_registration(name: &str) -> ComputationRegistration {
    ComputationRegistration {
        name: ComputationName::new(name).unwrap(),
        input_schema: test_input_schema(),
        output_schema: test_output_schema(),
        version: SchemaVersion::new(1, 0, 0),
        capability_required: ProfileKind::Remote,
        idempotency_class: IdempotencyClass::RequiresKey,
    }
}

fn valid_input() -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "action".to_string(),
        CanonicalValue::String("propagate".to_string()),
    );
    map.insert(
        "target".to_string(),
        CanonicalValue::String("node-1".to_string()),
    );
    CanonicalValue::Map(map)
}

// ---------------------------------------------------------------------------
// ComputationName — validation
// ---------------------------------------------------------------------------

#[test]
fn computation_name_valid_lowercase_underscores() {
    let name = ComputationName::new("revocation_propagate").unwrap();
    assert_eq!(name.as_str(), "revocation_propagate");
    assert_eq!(name.to_string(), "revocation_propagate");
}

#[test]
fn computation_name_with_dots_and_digits() {
    let name = ComputationName::new("evidence.sync.v2").unwrap();
    assert_eq!(name.as_str(), "evidence.sync.v2");
}

#[test]
fn computation_name_empty_rejected() {
    let err = ComputationName::new("").unwrap_err();
    assert!(matches!(err, RegistryError::InvalidComputationName { .. }));
    assert!(err.to_string().contains("empty"));
}

#[test]
fn computation_name_uppercase_rejected() {
    let err = ComputationName::new("MyComputation").unwrap_err();
    assert!(matches!(err, RegistryError::InvalidComputationName { .. }));
}

#[test]
fn computation_name_spaces_rejected() {
    assert!(ComputationName::new("my computation").is_err());
}

#[test]
fn computation_name_hyphens_rejected() {
    assert!(ComputationName::new("my-computation").is_err());
}

#[test]
fn computation_name_special_chars_rejected() {
    assert!(ComputationName::new("comp@name").is_err());
    assert!(ComputationName::new("comp!name").is_err());
    assert!(ComputationName::new("comp/name").is_err());
}

// ---------------------------------------------------------------------------
// SchemaVersionExt — compatibility
// ---------------------------------------------------------------------------

#[test]
fn schema_version_compatible_same_version() {
    let v = SchemaVersion::new(1, 0, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(1, 0, 0)));
}

#[test]
fn schema_version_compatible_higher_minor() {
    let v = SchemaVersion::new(1, 0, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(1, 3, 0)));
}

#[test]
fn schema_version_incompatible_different_major() {
    let v = SchemaVersion::new(1, 0, 0);
    assert!(!v.is_compatible_with(&SchemaVersion::new(2, 0, 0)));
}

#[test]
fn schema_version_incompatible_lower_minor() {
    let v = SchemaVersion::new(1, 3, 0);
    assert!(!v.is_compatible_with(&SchemaVersion::new(1, 2, 0)));
}

// ---------------------------------------------------------------------------
// IdempotencyClass
// ---------------------------------------------------------------------------

#[test]
fn idempotency_class_display() {
    assert_eq!(
        IdempotencyClass::NaturallyIdempotent.to_string(),
        "naturally_idempotent"
    );
    assert_eq!(IdempotencyClass::RequiresKey.to_string(), "requires_key");
}

// ---------------------------------------------------------------------------
// Registry — registration
// ---------------------------------------------------------------------------

#[test]
fn registry_new_is_empty() {
    let reg = RemoteComputationRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn registry_default_is_empty() {
    let reg = RemoteComputationRegistry::default();
    assert!(reg.is_empty());
}

#[test]
fn register_single_computation() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    assert_eq!(reg.len(), 1);
    assert!(!reg.is_empty());
}

#[test]
fn register_multiple_computations() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("alpha")).unwrap();
    reg.register(test_registration("beta")).unwrap();
    reg.register(test_registration("gamma")).unwrap();
    assert_eq!(reg.len(), 3);
}

#[test]
fn register_duplicate_rejected() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("dup")).unwrap();
    let err = reg.register(test_registration("dup")).unwrap_err();
    assert!(matches!(err, RegistryError::DuplicateRegistration { .. }));
    assert!(err.to_string().contains("already registered"));
}

#[test]
fn computation_names_sorted_deterministically() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("gamma")).unwrap();
    reg.register(test_registration("alpha")).unwrap();
    reg.register(test_registration("beta")).unwrap();
    assert_eq!(reg.computation_names(), vec!["alpha", "beta", "gamma"]);
}

// ---------------------------------------------------------------------------
// Registry — lookup
// ---------------------------------------------------------------------------

#[test]
fn lookup_registered_computation() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("evidence_sync")).unwrap();
    let name = ComputationName::new("evidence_sync").unwrap();
    let found = reg.lookup(&name).unwrap();
    assert_eq!(found.name.as_str(), "evidence_sync");
    assert_eq!(found.version, SchemaVersion::new(1, 0, 0));
    assert_eq!(found.capability_required, ProfileKind::Remote);
}

#[test]
fn lookup_missing_returns_none() {
    let reg = RemoteComputationRegistry::new();
    let name = ComputationName::new("nonexistent").unwrap();
    assert!(reg.lookup(&name).is_none());
}

// ---------------------------------------------------------------------------
// Registry — hot registration
// ---------------------------------------------------------------------------

#[test]
fn hot_register_with_evidence_emit_capability() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::policy();
    reg.hot_register(test_registration("late_addition"), &profile, "t1")
        .unwrap();
    assert_eq!(reg.len(), 1);
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "hot_registration");
    assert_eq!(events[0].outcome, "success");
}

#[test]
fn hot_register_without_evidence_emit_denied() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::compute_only();
    let err = reg
        .hot_register(test_registration("blocked"), &profile, "t1")
        .unwrap_err();
    assert!(matches!(err, RegistryError::HotRegistrationDenied { .. }));
    assert_eq!(reg.len(), 0);
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "denied");
}

#[test]
fn hot_register_duplicate_rejected() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::policy();
    reg.hot_register(test_registration("dup_hot"), &profile, "t1")
        .unwrap();
    let err = reg
        .hot_register(test_registration("dup_hot"), &profile, "t2")
        .unwrap_err();
    assert!(matches!(err, RegistryError::DuplicateRegistration { .. }));
}

// ---------------------------------------------------------------------------
// Registry — input validation
// ---------------------------------------------------------------------------

#[test]
fn validate_valid_input_returns_hash() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    let hash = reg.validate_input(&name, &valid_input(), "t1").unwrap();
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn validate_input_missing_field() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();

    let mut map = BTreeMap::new();
    map.insert(
        "action".to_string(),
        CanonicalValue::String("propagate".to_string()),
    );
    let input = CanonicalValue::Map(map);

    let err = reg.validate_input(&name, &input, "t1").unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    assert!(err.to_string().contains("missing"));
}

#[test]
fn validate_input_undeclared_field() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();

    let mut map = BTreeMap::new();
    map.insert(
        "action".to_string(),
        CanonicalValue::String("a".to_string()),
    );
    map.insert(
        "target".to_string(),
        CanonicalValue::String("b".to_string()),
    );
    map.insert("extra".to_string(), CanonicalValue::String("c".to_string()));
    let input = CanonicalValue::Map(map);

    let err = reg.validate_input(&name, &input, "t1").unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
    assert!(err.to_string().contains("undeclared"));
}

#[test]
fn validate_input_not_a_map() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();

    let input = CanonicalValue::String("not a map".to_string());
    let err = reg.validate_input(&name, &input, "t1").unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn validate_input_computation_not_found() {
    let mut reg = RemoteComputationRegistry::new();
    let name = ComputationName::new("missing").unwrap();
    let err = reg.validate_input(&name, &valid_input(), "t1").unwrap_err();
    assert!(matches!(err, RegistryError::ComputationNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Registry — deterministic input hashing
// ---------------------------------------------------------------------------

#[test]
fn input_hash_is_deterministic() {
    let name = ComputationName::new("test_comp").unwrap();
    let input = valid_input();
    let h1 = RemoteComputationRegistry::compute_input_hash(&name, &input);
    let h2 = RemoteComputationRegistry::compute_input_hash(&name, &input);
    assert_eq!(h1, h2);
}

#[test]
fn input_hash_differs_for_different_inputs() {
    let name = ComputationName::new("test_comp").unwrap();

    let mut map1 = BTreeMap::new();
    map1.insert(
        "action".to_string(),
        CanonicalValue::String("a".to_string()),
    );
    map1.insert(
        "target".to_string(),
        CanonicalValue::String("x".to_string()),
    );

    let mut map2 = BTreeMap::new();
    map2.insert(
        "action".to_string(),
        CanonicalValue::String("b".to_string()),
    );
    map2.insert(
        "target".to_string(),
        CanonicalValue::String("y".to_string()),
    );

    let h1 = RemoteComputationRegistry::compute_input_hash(&name, &CanonicalValue::Map(map1));
    let h2 = RemoteComputationRegistry::compute_input_hash(&name, &CanonicalValue::Map(map2));
    assert_ne!(h1, h2);
}

#[test]
fn input_hash_domain_separated_by_name() {
    let name_a = ComputationName::new("comp_a").unwrap();
    let name_b = ComputationName::new("comp_b").unwrap();
    let input = valid_input();
    let h1 = RemoteComputationRegistry::compute_input_hash(&name_a, &input);
    let h2 = RemoteComputationRegistry::compute_input_hash(&name_b, &input);
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Registry — capability enforcement
// ---------------------------------------------------------------------------

#[test]
fn capability_check_passes_with_remote_profile() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    reg.check_capability(&name, &CapabilityProfile::remote(), "t1")
        .unwrap();
}

#[test]
fn capability_check_passes_with_full_profile() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    reg.check_capability(&name, &CapabilityProfile::full(), "t1")
        .unwrap();
}

#[test]
fn capability_check_denied_with_compute_only() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    let err = reg
        .check_capability(&name, &CapabilityProfile::compute_only(), "t1")
        .unwrap_err();
    assert!(matches!(err, RegistryError::CapabilityDenied { .. }));
    assert!(err.to_string().contains("denied"));
}

#[test]
fn capability_check_computation_not_found() {
    let mut reg = RemoteComputationRegistry::new();
    let name = ComputationName::new("missing").unwrap();
    let err = reg
        .check_capability(&name, &CapabilityProfile::full(), "t1")
        .unwrap_err();
    assert!(matches!(err, RegistryError::ComputationNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Registry — version negotiation
// ---------------------------------------------------------------------------

#[test]
fn version_negotiation_compatible() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(1, 2, 0))
        .unwrap();
    assert!(result.compatible);
    assert_eq!(result.local_version, SchemaVersion::new(1, 0, 0));
    assert_eq!(result.remote_version, SchemaVersion::new(1, 2, 0));
}

#[test]
fn version_negotiation_exact_match() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(1, 0, 0))
        .unwrap();
    assert!(result.compatible);
}

#[test]
fn version_negotiation_incompatible_major() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(2, 0, 0))
        .unwrap();
    assert!(!result.compatible);
}

#[test]
fn version_negotiation_incompatible_lower_minor() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = test_registration("test_comp");
    comp.version = SchemaVersion::new(1, 3, 0);
    reg.register(comp).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(1, 1, 0))
        .unwrap();
    assert!(!result.compatible);
}

#[test]
fn version_negotiation_computation_not_found() {
    let reg = RemoteComputationRegistry::new();
    let name = ComputationName::new("missing").unwrap();
    let err = reg
        .negotiate_version(&name, SchemaVersion::new(1, 0, 0))
        .unwrap_err();
    assert!(matches!(err, RegistryError::ComputationNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Registry — closure rejection
// ---------------------------------------------------------------------------

#[test]
fn closure_rejection_returns_error() {
    let err = RemoteComputationRegistry::reject_closure("opaque function pointer");
    assert!(matches!(err, RegistryError::ClosureRejected { .. }));
    assert!(err.to_string().contains("opaque function pointer"));
}

// ---------------------------------------------------------------------------
// Registry — events and counters
// ---------------------------------------------------------------------------

#[test]
fn validation_success_emits_event() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    reg.validate_input(&name, &valid_input(), "trace-1")
        .unwrap();

    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "schema_validation");
    assert_eq!(events[0].outcome, "success");
    assert_eq!(events[0].trace_id, "trace-1");
    assert!(!events[0].input_hash.is_empty());
}

#[test]
fn validation_failure_emits_event() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    let _ = reg.validate_input(
        &name,
        &CanonicalValue::String("bad".to_string()),
        "trace-fail",
    );

    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "validation_failed");
}

#[test]
fn drain_events_clears_buffer() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();
    reg.validate_input(&name, &valid_input(), "t").unwrap();

    let e1 = reg.drain_events();
    assert_eq!(e1.len(), 1);
    let e2 = reg.drain_events();
    assert!(e2.is_empty());
}

#[test]
fn event_counts_track_outcomes() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("test_comp")).unwrap();
    let name = ComputationName::new("test_comp").unwrap();

    reg.validate_input(&name, &valid_input(), "t1").unwrap();
    reg.validate_input(&name, &valid_input(), "t2").unwrap();
    let _ = reg.validate_input(&name, &CanonicalValue::String("bad".to_string()), "t3");

    assert_eq!(reg.event_counts().get("validation_success"), Some(&2));
    assert_eq!(reg.event_counts().get("validation_failed"), Some(&1));
}

// ---------------------------------------------------------------------------
// RegistryError — display coverage
// ---------------------------------------------------------------------------

#[test]
fn registry_error_display_all_variants() {
    let errors: Vec<(RegistryError, &str)> = vec![
        (
            RegistryError::InvalidComputationName {
                name: "bad".to_string(),
                reason: "empty".to_string(),
            },
            "invalid",
        ),
        (
            RegistryError::DuplicateRegistration {
                name: "dup".to_string(),
            },
            "already registered",
        ),
        (
            RegistryError::ComputationNotFound {
                name: "missing".to_string(),
            },
            "not found",
        ),
        (
            RegistryError::SchemaValidationFailed {
                computation_name: "comp".to_string(),
                reason: "bad field".to_string(),
            },
            "validation failed",
        ),
        (
            RegistryError::CapabilityDenied {
                computation_name: "comp".to_string(),
                required: ProfileKind::Remote,
                held: ProfileKind::ComputeOnly,
            },
            "denied",
        ),
        (
            RegistryError::VersionIncompatible {
                computation_name: "comp".to_string(),
                registered: SchemaVersion::new(1, 0, 0),
                requested: SchemaVersion::new(2, 0, 0),
            },
            "incompatible",
        ),
        (
            RegistryError::ClosureRejected {
                reason: "no closures".to_string(),
            },
            "rejected",
        ),
        (
            RegistryError::HotRegistrationDenied {
                reason: "no cap".to_string(),
            },
            "denied",
        ),
    ];
    for (err, expected_substr) in &errors {
        let msg = format!("{err}");
        assert!(
            msg.contains(expected_substr),
            "'{msg}' should contain '{expected_substr}'"
        );
    }
}

#[test]
fn registry_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(RegistryError::ComputationNotFound {
        name: "test".to_string(),
    });
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn computation_name_serde_roundtrip() {
    let name = ComputationName::new("evidence_sync").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    let decoded: ComputationName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, decoded);
}

#[test]
fn idempotency_class_serde_roundtrip() {
    for class in [
        IdempotencyClass::NaturallyIdempotent,
        IdempotencyClass::RequiresKey,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let decoded: IdempotencyClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, decoded);
    }
}

#[test]
fn registration_serde_roundtrip() {
    let reg = test_registration("evidence_sync");
    let json = serde_json::to_string(&reg).unwrap();
    let decoded: ComputationRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, decoded);
}

#[test]
fn registry_event_serde_roundtrip() {
    let event = RegistryEvent {
        trace_id: "trace-1".to_string(),
        component: "registry".to_string(),
        computation_name: "test_comp".to_string(),
        version: "1.0".to_string(),
        input_hash: "abcdef".to_string(),
        event: "schema_validation".to_string(),
        outcome: "success".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: RegistryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn registry_error_serde_roundtrip() {
    let errors = vec![
        RegistryError::InvalidComputationName {
            name: "bad".to_string(),
            reason: "empty".to_string(),
        },
        RegistryError::DuplicateRegistration {
            name: "dup".to_string(),
        },
        RegistryError::ComputationNotFound {
            name: "missing".to_string(),
        },
        RegistryError::ClosureRejected {
            reason: "no closures".to_string(),
        },
        RegistryError::HotRegistrationDenied {
            reason: "no cap".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: RegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

#[test]
fn version_negotiation_result_serde_roundtrip() {
    let result = VersionNegotiationResult {
        computation_name: ComputationName::new("test_comp").unwrap(),
        compatible: true,
        local_version: SchemaVersion::new(1, 0, 0),
        remote_version: SchemaVersion::new(1, 2, 0),
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_register_validate_check_negotiate() {
    let mut reg = RemoteComputationRegistry::new();

    // 1. Register
    reg.register(test_registration("revocation_propagate"))
        .unwrap();

    let name = ComputationName::new("revocation_propagate").unwrap();

    // 2. Check capability
    reg.check_capability(&name, &CapabilityProfile::remote(), "t1")
        .unwrap();

    // 3. Validate input
    let input_hash = reg.validate_input(&name, &valid_input(), "t2").unwrap();
    assert_eq!(input_hash.as_bytes().len(), 32);

    // 4. Negotiate version
    let negotiation = reg
        .negotiate_version(&name, SchemaVersion::new(1, 1, 0))
        .unwrap();
    assert!(negotiation.compatible);

    // 5. Compute idempotency hash
    let idem_hash = RemoteComputationRegistry::compute_input_hash(&name, &valid_input());
    assert_eq!(idem_hash.as_bytes().len(), 32);

    // 6. Verify events
    let events = reg.drain_events();
    assert!(!events.is_empty());
}

#[test]
fn registration_count_increments_in_event_counts() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("a")).unwrap();
    reg.register(test_registration("b")).unwrap();
    assert_eq!(reg.event_counts().get("registration"), Some(&2));
}

// ---------------------------------------------------------------------------
// Enrichment tests — PearlTower 2026-03-12
// ---------------------------------------------------------------------------

// -- ComputationName: Clone, Debug, Display, Ord, serde --

#[test]
fn enrichment_computation_name_clone_is_equal() {
    let orig = ComputationName::new("clone_check").unwrap();
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
    assert_eq!(orig.as_str(), cloned.as_str());
}

#[test]
fn enrichment_computation_name_debug_contains_inner_string() {
    let name = ComputationName::new("debug_inner").unwrap();
    let d = format!("{name:?}");
    assert!(d.contains("debug_inner"));
    assert!(d.contains("ComputationName"));
}

#[test]
fn enrichment_computation_name_display_equals_as_str() {
    let name = ComputationName::new("display_equiv").unwrap();
    assert_eq!(format!("{name}"), name.as_str());
}

#[test]
fn enrichment_computation_name_ord_is_lexicographic() {
    let a = ComputationName::new("alpha").unwrap();
    let b = ComputationName::new("beta").unwrap();
    let z = ComputationName::new("zeta").unwrap();
    assert!(a < b);
    assert!(b < z);
    assert!(a < z);
}

#[test]
fn enrichment_computation_name_eq_reflexive() {
    let name = ComputationName::new("reflexive").unwrap();
    assert_eq!(name, name.clone());
}

#[test]
fn enrichment_computation_name_ne_for_different() {
    let a = ComputationName::new("alpha").unwrap();
    let b = ComputationName::new("beta").unwrap();
    assert_ne!(a, b);
}

#[test]
fn enrichment_computation_name_serde_json_is_quoted_string() {
    let name = ComputationName::new("json_check").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    assert!(json.starts_with('"'));
    assert!(json.ends_with('"'));
    assert!(json.contains("json_check"));
}

#[test]
fn enrichment_computation_name_serde_roundtrip_with_dots() {
    let name = ComputationName::new("a.b.c.d").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    let back: ComputationName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

#[test]
fn enrichment_computation_name_serde_roundtrip_digits_only() {
    let name = ComputationName::new("12345").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    let back: ComputationName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

#[test]
fn enrichment_computation_name_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let name = ComputationName::new("hash_test").unwrap();
    let mut h1 = DefaultHasher::new();
    name.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    name.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn enrichment_computation_name_hash_differs_for_distinct() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let a = ComputationName::new("aaa").unwrap();
    let b = ComputationName::new("bbb").unwrap();
    let mut h1 = DefaultHasher::new();
    a.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    b.hash(&mut h2);
    assert_ne!(h1.finish(), h2.finish());
}

// -- ComputationName: validation edge cases --

#[test]
fn enrichment_computation_name_single_underscore_valid() {
    let name = ComputationName::new("_").unwrap();
    assert_eq!(name.as_str(), "_");
}

#[test]
fn enrichment_computation_name_single_dot_valid() {
    let name = ComputationName::new(".").unwrap();
    assert_eq!(name.as_str(), ".");
}

#[test]
fn enrichment_computation_name_single_digit_valid() {
    let name = ComputationName::new("0").unwrap();
    assert_eq!(name.as_str(), "0");
}

#[test]
fn enrichment_computation_name_tab_rejected() {
    assert!(ComputationName::new("a\tb").is_err());
}

#[test]
fn enrichment_computation_name_newline_rejected() {
    assert!(ComputationName::new("a\nb").is_err());
}

#[test]
fn enrichment_computation_name_unicode_rejected() {
    assert!(ComputationName::new("caf\u{00e9}").is_err());
}

#[test]
fn enrichment_computation_name_colon_rejected() {
    assert!(ComputationName::new("a:b").is_err());
}

#[test]
fn enrichment_computation_name_tilde_rejected() {
    assert!(ComputationName::new("a~b").is_err());
}

#[test]
fn enrichment_computation_name_long_name_valid() {
    let long = "a".repeat(1000);
    let name = ComputationName::new(&long).unwrap();
    assert_eq!(name.as_str().len(), 1000);
}

#[test]
fn enrichment_computation_name_error_contains_offending_name() {
    let err = ComputationName::new("BAD_NAME").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("BAD_NAME"));
}

// -- IdempotencyClass: Clone, Debug, Copy, Ord, serde --

#[test]
fn enrichment_idempotency_class_copy_semantics() {
    let a = IdempotencyClass::NaturallyIdempotent;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_idempotency_class_debug_variants() {
    let ni = format!("{:?}", IdempotencyClass::NaturallyIdempotent);
    let rk = format!("{:?}", IdempotencyClass::RequiresKey);
    assert!(ni.contains("NaturallyIdempotent"));
    assert!(rk.contains("RequiresKey"));
    assert_ne!(ni, rk);
}

#[test]
fn enrichment_idempotency_class_ord() {
    assert!(IdempotencyClass::NaturallyIdempotent < IdempotencyClass::RequiresKey);
}

#[test]
fn enrichment_idempotency_class_display_distinct() {
    let a = IdempotencyClass::NaturallyIdempotent.to_string();
    let b = IdempotencyClass::RequiresKey.to_string();
    assert_ne!(a, b);
    assert!(!a.is_empty());
    assert!(!b.is_empty());
}

#[test]
fn enrichment_idempotency_class_serde_naturally_idempotent_json_value() {
    let json = serde_json::to_string(&IdempotencyClass::NaturallyIdempotent).unwrap();
    assert!(json.contains("NaturallyIdempotent"));
}

#[test]
fn enrichment_idempotency_class_serde_requires_key_json_value() {
    let json = serde_json::to_string(&IdempotencyClass::RequiresKey).unwrap();
    assert!(json.contains("RequiresKey"));
}

// -- ComputationSchema: Clone, Debug, serde --

#[test]
fn enrichment_computation_schema_clone_equality() {
    let orig = test_input_schema();
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
}

#[test]
fn enrichment_computation_schema_debug_contains_type_name() {
    let s = test_input_schema();
    let d = format!("{s:?}");
    assert!(d.contains("ComputationSchema"));
    assert!(d.contains("test input schema"));
}

#[test]
fn enrichment_computation_schema_serde_roundtrip() {
    let schema = ComputationSchema::new(
        "enrichment schema",
        b"enrichment-def-v1",
        vec!["x".to_string(), "y".to_string(), "z".to_string()],
    );
    let json = serde_json::to_string(&schema).unwrap();
    let back: ComputationSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

#[test]
fn enrichment_computation_schema_json_field_names_stable() {
    let schema = test_input_schema();
    let json = serde_json::to_string(&schema).unwrap();
    assert!(json.contains("\"description\""));
    assert!(json.contains("\"schema_hash\""));
    assert!(json.contains("\"expected_fields\""));
}

#[test]
fn enrichment_computation_schema_empty_fields() {
    let schema = ComputationSchema::new("empty fields schema", b"empty-def", vec![]);
    assert!(schema.expected_fields.is_empty());
    let json = serde_json::to_string(&schema).unwrap();
    let back: ComputationSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

#[test]
fn enrichment_computation_schema_hash_deterministic() {
    let a = ComputationSchema::new("det", b"same-bytes", vec!["f".into()]);
    let b = ComputationSchema::new("det", b"same-bytes", vec!["f".into()]);
    assert_eq!(a.schema_hash, b.schema_hash);
}

#[test]
fn enrichment_computation_schema_hash_differs_for_different_defs() {
    let a = ComputationSchema::new("a", b"def-alpha", vec!["f".into()]);
    let b = ComputationSchema::new("a", b"def-beta", vec!["f".into()]);
    assert_ne!(a.schema_hash, b.schema_hash);
}

// -- ComputationRegistration: Clone, Debug, serde --

#[test]
fn enrichment_computation_registration_clone_equality() {
    let orig = test_registration("clone_reg");
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
}

#[test]
fn enrichment_computation_registration_debug_contains_name() {
    let reg = test_registration("debug_reg");
    let d = format!("{reg:?}");
    assert!(d.contains("debug_reg"));
    assert!(d.contains("ComputationRegistration"));
}

#[test]
fn enrichment_computation_registration_serde_roundtrip_naturally_idempotent() {
    let reg = ComputationRegistration {
        name: ComputationName::new("nat_idem").unwrap(),
        input_schema: test_input_schema(),
        output_schema: test_output_schema(),
        version: SchemaVersion::new(2, 1, 3),
        capability_required: ProfileKind::Full,
        idempotency_class: IdempotencyClass::NaturallyIdempotent,
    };
    let json = serde_json::to_string(&reg).unwrap();
    let back: ComputationRegistration = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

#[test]
fn enrichment_computation_registration_json_field_names() {
    let reg = test_registration("field_names");
    let json = serde_json::to_string(&reg).unwrap();
    for field in [
        "\"name\"",
        "\"input_schema\"",
        "\"output_schema\"",
        "\"version\"",
        "\"capability_required\"",
        "\"idempotency_class\"",
    ] {
        assert!(json.contains(field), "missing field {field} in JSON");
    }
}

#[test]
fn enrichment_computation_registration_all_profile_kinds_serde() {
    for kind in [
        ProfileKind::Full,
        ProfileKind::EngineCore,
        ProfileKind::Policy,
        ProfileKind::Remote,
        ProfileKind::ComputeOnly,
    ] {
        let reg = ComputationRegistration {
            name: ComputationName::new("pk_test").unwrap(),
            input_schema: test_input_schema(),
            output_schema: test_output_schema(),
            version: SchemaVersion::new(1, 0, 0),
            capability_required: kind,
            idempotency_class: IdempotencyClass::RequiresKey,
        };
        let json = serde_json::to_string(&reg).unwrap();
        let back: ComputationRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, back);
    }
}

// -- RegistryEvent: Clone, Debug, serde --

#[test]
fn enrichment_registry_event_clone_equality() {
    let ev = RegistryEvent {
        trace_id: "t".into(),
        component: "c".into(),
        computation_name: "n".into(),
        version: "1.0.0".into(),
        input_hash: "h".into(),
        event: "e".into(),
        outcome: "o".into(),
    };
    let cloned = ev.clone();
    assert_eq!(ev, cloned);
}

#[test]
fn enrichment_registry_event_debug_contains_fields() {
    let ev = RegistryEvent {
        trace_id: "trace_debug".into(),
        component: "comp_debug".into(),
        computation_name: "name_debug".into(),
        version: "9.8.7".into(),
        input_hash: "hashval".into(),
        event: "event_type".into(),
        outcome: "outcome_val".into(),
    };
    let d = format!("{ev:?}");
    assert!(d.contains("trace_debug"));
    assert!(d.contains("RegistryEvent"));
}

#[test]
fn enrichment_registry_event_json_field_names() {
    let ev = RegistryEvent {
        trace_id: "t".into(),
        component: "c".into(),
        computation_name: "n".into(),
        version: "v".into(),
        input_hash: "h".into(),
        event: "e".into(),
        outcome: "o".into(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    for field in [
        "\"trace_id\"",
        "\"component\"",
        "\"computation_name\"",
        "\"version\"",
        "\"input_hash\"",
        "\"event\"",
        "\"outcome\"",
    ] {
        assert!(json.contains(field), "missing {field}");
    }
}

#[test]
fn enrichment_registry_event_ne_for_different_trace_id() {
    let a = RegistryEvent {
        trace_id: "t1".into(),
        component: "c".into(),
        computation_name: "n".into(),
        version: "v".into(),
        input_hash: "h".into(),
        event: "e".into(),
        outcome: "o".into(),
    };
    let mut b = a.clone();
    b.trace_id = "t2".into();
    assert_ne!(a, b);
}

// -- RegistryError: Clone, Debug, Display, serde --

#[test]
fn enrichment_registry_error_clone_all_variants() {
    let variants: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName {
            name: "n".into(),
            reason: "r".into(),
        },
        RegistryError::DuplicateRegistration { name: "n".into() },
        RegistryError::ComputationNotFound { name: "n".into() },
        RegistryError::SchemaValidationFailed {
            computation_name: "n".into(),
            reason: "r".into(),
        },
        RegistryError::CapabilityDenied {
            computation_name: "n".into(),
            required: ProfileKind::Remote,
            held: ProfileKind::ComputeOnly,
        },
        RegistryError::VersionIncompatible {
            computation_name: "n".into(),
            registered: SchemaVersion::new(1, 0, 0),
            requested: SchemaVersion::new(2, 0, 0),
        },
        RegistryError::ClosureRejected { reason: "r".into() },
        RegistryError::HotRegistrationDenied { reason: "r".into() },
    ];
    for err in &variants {
        let cloned = err.clone();
        assert_eq!(*err, cloned);
    }
}

#[test]
fn enrichment_registry_error_debug_all_variants() {
    let variant_names = [
        "InvalidComputationName",
        "DuplicateRegistration",
        "ComputationNotFound",
        "SchemaValidationFailed",
        "CapabilityDenied",
        "VersionIncompatible",
        "ClosureRejected",
        "HotRegistrationDenied",
    ];
    let variants: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName {
            name: "n".into(),
            reason: "r".into(),
        },
        RegistryError::DuplicateRegistration { name: "n".into() },
        RegistryError::ComputationNotFound { name: "n".into() },
        RegistryError::SchemaValidationFailed {
            computation_name: "n".into(),
            reason: "r".into(),
        },
        RegistryError::CapabilityDenied {
            computation_name: "n".into(),
            required: ProfileKind::Remote,
            held: ProfileKind::ComputeOnly,
        },
        RegistryError::VersionIncompatible {
            computation_name: "n".into(),
            registered: SchemaVersion::new(1, 0, 0),
            requested: SchemaVersion::new(2, 0, 0),
        },
        RegistryError::ClosureRejected { reason: "r".into() },
        RegistryError::HotRegistrationDenied { reason: "r".into() },
    ];
    for (err, expected_name) in variants.iter().zip(variant_names.iter()) {
        let d = format!("{err:?}");
        assert!(d.contains(expected_name), "{d} missing {expected_name}");
    }
}

#[test]
fn enrichment_registry_error_display_invalid_name_format() {
    let e = RegistryError::InvalidComputationName {
        name: "FOO".into(),
        reason: "uppercase".into(),
    };
    let s = e.to_string();
    assert!(s.contains("invalid computation name"));
    assert!(s.contains("'FOO'"));
    assert!(s.contains("uppercase"));
}

#[test]
fn enrichment_registry_error_display_duplicate_format() {
    let e = RegistryError::DuplicateRegistration {
        name: "dup_name".into(),
    };
    let s = e.to_string();
    assert!(s.contains("'dup_name'"));
    assert!(s.contains("already registered"));
}

#[test]
fn enrichment_registry_error_display_not_found_format() {
    let e = RegistryError::ComputationNotFound {
        name: "missing_comp".into(),
    };
    let s = e.to_string();
    assert!(s.contains("'missing_comp'"));
    assert!(s.contains("not found"));
}

#[test]
fn enrichment_registry_error_display_schema_failed_format() {
    let e = RegistryError::SchemaValidationFailed {
        computation_name: "sc".into(),
        reason: "extra fields".into(),
    };
    let s = e.to_string();
    assert!(s.contains("schema validation failed"));
    assert!(s.contains("'sc'"));
    assert!(s.contains("extra fields"));
}

#[test]
fn enrichment_registry_error_display_capability_denied_format() {
    let e = RegistryError::CapabilityDenied {
        computation_name: "cap_comp".into(),
        required: ProfileKind::Remote,
        held: ProfileKind::ComputeOnly,
    };
    let s = e.to_string();
    assert!(s.contains("capability denied"));
    assert!(s.contains("'cap_comp'"));
}

#[test]
fn enrichment_registry_error_display_version_incompatible_format() {
    let e = RegistryError::VersionIncompatible {
        computation_name: "ver_comp".into(),
        registered: SchemaVersion::new(3, 2, 1),
        requested: SchemaVersion::new(4, 0, 0),
    };
    let s = e.to_string();
    assert!(s.contains("version incompatible"));
    assert!(s.contains("'ver_comp'"));
    assert!(s.contains("3.2.1"));
    assert!(s.contains("4.0.0"));
}

#[test]
fn enrichment_registry_error_display_closure_rejected_format() {
    let e = RegistryError::ClosureRejected {
        reason: "opaque blob".into(),
    };
    let s = e.to_string();
    assert!(s.contains("closure"));
    assert!(s.contains("rejected"));
    assert!(s.contains("opaque blob"));
}

#[test]
fn enrichment_registry_error_display_hot_denied_format() {
    let e = RegistryError::HotRegistrationDenied {
        reason: "no evidence_emit".into(),
    };
    let s = e.to_string();
    assert!(s.contains("hot-registration denied"));
    assert!(s.contains("no evidence_emit"));
}

#[test]
fn enrichment_registry_error_is_std_error_all_variants() {
    let variants: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName {
            name: "n".into(),
            reason: "r".into(),
        },
        RegistryError::DuplicateRegistration { name: "n".into() },
        RegistryError::ComputationNotFound { name: "n".into() },
        RegistryError::SchemaValidationFailed {
            computation_name: "n".into(),
            reason: "r".into(),
        },
        RegistryError::CapabilityDenied {
            computation_name: "n".into(),
            required: ProfileKind::Remote,
            held: ProfileKind::ComputeOnly,
        },
        RegistryError::VersionIncompatible {
            computation_name: "n".into(),
            registered: SchemaVersion::new(1, 0, 0),
            requested: SchemaVersion::new(2, 0, 0),
        },
        RegistryError::ClosureRejected { reason: "r".into() },
        RegistryError::HotRegistrationDenied { reason: "r".into() },
    ];
    for err in variants {
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(!boxed.to_string().is_empty());
    }
}

#[test]
fn enrichment_registry_error_serde_all_eight_variants_roundtrip() {
    let variants: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName {
            name: "x".into(),
            reason: "y".into(),
        },
        RegistryError::DuplicateRegistration { name: "x".into() },
        RegistryError::ComputationNotFound { name: "x".into() },
        RegistryError::SchemaValidationFailed {
            computation_name: "x".into(),
            reason: "y".into(),
        },
        RegistryError::CapabilityDenied {
            computation_name: "x".into(),
            required: ProfileKind::Policy,
            held: ProfileKind::EngineCore,
        },
        RegistryError::VersionIncompatible {
            computation_name: "x".into(),
            registered: SchemaVersion::new(5, 0, 0),
            requested: SchemaVersion::new(6, 0, 0),
        },
        RegistryError::ClosureRejected { reason: "x".into() },
        RegistryError::HotRegistrationDenied { reason: "x".into() },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: RegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_registry_error_serde_json_distinct_per_variant() {
    let variants: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName {
            name: "z".into(),
            reason: "z".into(),
        },
        RegistryError::DuplicateRegistration { name: "z".into() },
        RegistryError::ComputationNotFound { name: "z".into() },
        RegistryError::SchemaValidationFailed {
            computation_name: "z".into(),
            reason: "z".into(),
        },
        RegistryError::CapabilityDenied {
            computation_name: "z".into(),
            required: ProfileKind::Full,
            held: ProfileKind::ComputeOnly,
        },
        RegistryError::VersionIncompatible {
            computation_name: "z".into(),
            registered: SchemaVersion::new(1, 0, 0),
            requested: SchemaVersion::new(2, 0, 0),
        },
        RegistryError::ClosureRejected { reason: "z".into() },
        RegistryError::HotRegistrationDenied { reason: "z".into() },
    ];
    let jsons: std::collections::BTreeSet<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(jsons.len(), variants.len());
}

// -- VersionNegotiationResult: Clone, Debug, serde --

#[test]
fn enrichment_version_negotiation_result_clone() {
    let orig = VersionNegotiationResult {
        computation_name: ComputationName::new("clone_neg").unwrap(),
        compatible: true,
        local_version: SchemaVersion::new(1, 0, 0),
        remote_version: SchemaVersion::new(1, 5, 0),
    };
    let cloned = orig.clone();
    assert_eq!(orig, cloned);
}

#[test]
fn enrichment_version_negotiation_result_debug() {
    let r = VersionNegotiationResult {
        computation_name: ComputationName::new("dbg_neg").unwrap(),
        compatible: false,
        local_version: SchemaVersion::new(2, 0, 0),
        remote_version: SchemaVersion::new(3, 0, 0),
    };
    let d = format!("{r:?}");
    assert!(d.contains("VersionNegotiationResult"));
    assert!(d.contains("dbg_neg"));
}

#[test]
fn enrichment_version_negotiation_result_json_fields() {
    let r = VersionNegotiationResult {
        computation_name: ComputationName::new("jf").unwrap(),
        compatible: false,
        local_version: SchemaVersion::new(1, 0, 0),
        remote_version: SchemaVersion::new(2, 0, 0),
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"computation_name\""));
    assert!(json.contains("\"compatible\""));
    assert!(json.contains("\"local_version\""));
    assert!(json.contains("\"remote_version\""));
}

#[test]
fn enrichment_version_negotiation_result_serde_compatible_roundtrip() {
    let r = VersionNegotiationResult {
        computation_name: ComputationName::new("compat_rt").unwrap(),
        compatible: true,
        local_version: SchemaVersion::new(1, 0, 0),
        remote_version: SchemaVersion::new(1, 99, 0),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_version_negotiation_result_serde_incompatible_roundtrip() {
    let r = VersionNegotiationResult {
        computation_name: ComputationName::new("incompat_rt").unwrap(),
        compatible: false,
        local_version: SchemaVersion::new(5, 3, 1),
        remote_version: SchemaVersion::new(6, 0, 0),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// -- SchemaVersionExt: edge cases --

#[test]
fn enrichment_schema_version_compatible_same_high_minor() {
    let v = SchemaVersion::new(1, 50, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(1, 50, 0)));
}

#[test]
fn enrichment_schema_version_compatible_patch_ignored() {
    // Patch level should not affect compatibility (same major/minor)
    let v = SchemaVersion::new(1, 0, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(1, 0, 99)));
}

#[test]
fn enrichment_schema_version_incompatible_zero_vs_one_major() {
    let v = SchemaVersion::new(0, 5, 0);
    assert!(!v.is_compatible_with(&SchemaVersion::new(1, 0, 0)));
}

#[test]
fn enrichment_schema_version_compatible_forward_minor_many() {
    let v = SchemaVersion::new(3, 0, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(3, 100, 0)));
}

// -- Registry: deterministic hashing --

#[test]
fn enrichment_compute_input_hash_deterministic_across_calls() {
    let name = ComputationName::new("det_hash").unwrap();
    let input = valid_input();
    let hashes: Vec<_> = (0..10)
        .map(|_| RemoteComputationRegistry::compute_input_hash(&name, &input))
        .collect();
    for h in &hashes {
        assert_eq!(h, &hashes[0]);
    }
}

#[test]
fn enrichment_compute_input_hash_length_always_32() {
    let name = ComputationName::new("len_check").unwrap();
    let inputs = vec![
        CanonicalValue::Null,
        CanonicalValue::Bool(true),
        CanonicalValue::U64(42),
        CanonicalValue::I64(-1),
        CanonicalValue::String("hello".into()),
        CanonicalValue::Bytes(vec![1, 2, 3]),
        CanonicalValue::Array(vec![CanonicalValue::U64(1)]),
        valid_input(),
    ];
    for input in &inputs {
        let h = RemoteComputationRegistry::compute_input_hash(&name, input);
        assert_eq!(h.as_bytes().len(), 32);
    }
}

#[test]
fn enrichment_compute_input_hash_different_value_types_differ() {
    let name = ComputationName::new("type_diff").unwrap();
    let h_null = RemoteComputationRegistry::compute_input_hash(&name, &CanonicalValue::Null);
    let h_bool = RemoteComputationRegistry::compute_input_hash(&name, &CanonicalValue::Bool(false));
    let h_u64 = RemoteComputationRegistry::compute_input_hash(&name, &CanonicalValue::U64(0));
    assert_ne!(h_null, h_bool);
    assert_ne!(h_null, h_u64);
    assert_ne!(h_bool, h_u64);
}

#[test]
fn enrichment_compute_input_hash_hex_is_64_chars() {
    let name = ComputationName::new("hex_check").unwrap();
    let h = RemoteComputationRegistry::compute_input_hash(&name, &valid_input());
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

// -- Registry: input validation edge cases --

#[test]
fn enrichment_validate_input_bool_rejected_as_non_map() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("bool_comp")).unwrap();
    let name = ComputationName::new("bool_comp").unwrap();
    let err = reg
        .validate_input(&name, &CanonicalValue::Bool(true), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrichment_validate_input_u64_rejected_as_non_map() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("u64_comp")).unwrap();
    let name = ComputationName::new("u64_comp").unwrap();
    let err = reg
        .validate_input(&name, &CanonicalValue::U64(999), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrichment_validate_input_i64_rejected_as_non_map() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("i64_comp")).unwrap();
    let name = ComputationName::new("i64_comp").unwrap();
    let err = reg
        .validate_input(&name, &CanonicalValue::I64(-42), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrichment_validate_input_bytes_rejected_as_non_map() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("bytes_comp")).unwrap();
    let name = ComputationName::new("bytes_comp").unwrap();
    let err = reg
        .validate_input(&name, &CanonicalValue::Bytes(vec![0xDE, 0xAD]), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrichment_validate_input_empty_schema_accepts_empty_map() {
    let mut reg = RemoteComputationRegistry::new();
    let registration = ComputationRegistration {
        name: ComputationName::new("empty_schema").unwrap(),
        input_schema: ComputationSchema::new("empty", b"empty-def", vec![]),
        output_schema: test_output_schema(),
        version: SchemaVersion::new(1, 0, 0),
        capability_required: ProfileKind::Remote,
        idempotency_class: IdempotencyClass::NaturallyIdempotent,
    };
    reg.register(registration).unwrap();
    let name = ComputationName::new("empty_schema").unwrap();
    let empty_map = CanonicalValue::Map(BTreeMap::new());
    let hash = reg.validate_input(&name, &empty_map, "t").unwrap();
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn enrichment_validate_input_empty_schema_rejects_non_empty_map() {
    let mut reg = RemoteComputationRegistry::new();
    let registration = ComputationRegistration {
        name: ComputationName::new("empty_schema_strict").unwrap(),
        input_schema: ComputationSchema::new("empty strict", b"empty-strict-def", vec![]),
        output_schema: test_output_schema(),
        version: SchemaVersion::new(1, 0, 0),
        capability_required: ProfileKind::Remote,
        idempotency_class: IdempotencyClass::NaturallyIdempotent,
    };
    reg.register(registration).unwrap();
    let name = ComputationName::new("empty_schema_strict").unwrap();
    let mut map = BTreeMap::new();
    map.insert("sneaky".into(), CanonicalValue::U64(1));
    let err = reg
        .validate_input(&name, &CanonicalValue::Map(map), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrichment_validate_input_hash_matches_compute_input_hash() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("hash_match")).unwrap();
    let name = ComputationName::new("hash_match").unwrap();
    let input = valid_input();
    let validated_hash = reg.validate_input(&name, &input, "t").unwrap();
    // The validate_input hash is ContentHash::compute(encode_value(input)),
    // while compute_input_hash includes the computation name as a domain separator.
    // They should be DIFFERENT since compute_input_hash prepends the name.
    let standalone_hash = RemoteComputationRegistry::compute_input_hash(&name, &input);
    // Both are 32 bytes
    assert_eq!(validated_hash.as_bytes().len(), 32);
    assert_eq!(standalone_hash.as_bytes().len(), 32);
    // They differ because compute_input_hash includes the name prefix
    assert_ne!(validated_hash, standalone_hash);
}

// -- Registry: capability enforcement edge cases --

#[test]
fn enrichment_capability_check_engine_core_denied_for_remote_required() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("engine_check")).unwrap();
    let name = ComputationName::new("engine_check").unwrap();
    let err = reg
        .check_capability(&name, &CapabilityProfile::engine_core(), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::CapabilityDenied { .. }));
}

#[test]
fn enrichment_capability_check_policy_denied_for_remote_required() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("policy_check")).unwrap();
    let name = ComputationName::new("policy_check").unwrap();
    let err = reg
        .check_capability(&name, &CapabilityProfile::policy(), "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::CapabilityDenied { .. }));
}

#[test]
fn enrichment_capability_denied_event_has_correct_fields() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("ev_cap")).unwrap();
    let name = ComputationName::new("ev_cap").unwrap();
    let _ = reg.check_capability(&name, &CapabilityProfile::compute_only(), "trace_ev_cap");
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "capability_check");
    assert_eq!(events[0].outcome, "denied");
    assert_eq!(events[0].trace_id, "trace_ev_cap");
    assert_eq!(events[0].computation_name, "ev_cap");
    assert_eq!(events[0].component, "registry");
}

// -- Registry: version negotiation edge cases --

#[test]
fn enrichment_version_negotiation_result_carries_computation_name() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("name_carry")).unwrap();
    let name = ComputationName::new("name_carry").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(1, 0, 0))
        .unwrap();
    assert_eq!(result.computation_name.as_str(), "name_carry");
}

#[test]
fn enrichment_version_negotiation_patch_difference_still_compatible() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = test_registration("patch_test");
    comp.version = SchemaVersion::new(2, 3, 0);
    reg.register(comp).unwrap();
    let name = ComputationName::new("patch_test").unwrap();
    let result = reg
        .negotiate_version(&name, SchemaVersion::new(2, 3, 99))
        .unwrap();
    assert!(result.compatible);
}

// -- Registry: hot registration edge cases --

#[test]
fn enrichment_hot_register_with_full_profile_succeeds() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::full();
    reg.hot_register(test_registration("hot_full"), &profile, "t")
        .unwrap();
    assert_eq!(reg.len(), 1);
}

#[test]
fn enrichment_hot_register_with_engine_core_denied() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::engine_core();
    let err = reg
        .hot_register(test_registration("hot_ec"), &profile, "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::HotRegistrationDenied { .. }));
    assert_eq!(reg.len(), 0);
}

#[test]
fn enrichment_hot_register_with_remote_profile_denied() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::remote();
    let err = reg
        .hot_register(test_registration("hot_remote"), &profile, "t")
        .unwrap_err();
    assert!(matches!(err, RegistryError::HotRegistrationDenied { .. }));
}

#[test]
fn enrichment_hot_register_denied_event_has_computation_name() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::compute_only();
    let _ = reg.hot_register(test_registration("hot_denied_name"), &profile, "trace_hdn");
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].computation_name, "hot_denied_name");
    assert_eq!(events[0].trace_id, "trace_hdn");
}

// -- Registry: events and counters edge cases --

#[test]
fn enrichment_drain_events_idempotent_on_empty() {
    let mut reg = RemoteComputationRegistry::new();
    assert!(reg.drain_events().is_empty());
    assert!(reg.drain_events().is_empty());
    assert!(reg.drain_events().is_empty());
}

#[test]
fn enrichment_event_counts_empty_on_fresh_registry() {
    let reg = RemoteComputationRegistry::new();
    assert!(reg.event_counts().is_empty());
}

#[test]
fn enrichment_event_counts_accumulate_across_operations() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("acc_a")).unwrap();
    reg.register(test_registration("acc_b")).unwrap();
    let name = ComputationName::new("acc_a").unwrap();
    reg.validate_input(&name, &valid_input(), "t1").unwrap();
    let _ = reg.validate_input(&name, &CanonicalValue::Null, "t2");
    reg.check_capability(&name, &CapabilityProfile::remote(), "t3")
        .unwrap();
    let _ = reg.check_capability(&name, &CapabilityProfile::compute_only(), "t4");

    let counts = reg.event_counts();
    assert_eq!(counts.get("registration"), Some(&2));
    assert_eq!(counts.get("validation_success"), Some(&1));
    assert_eq!(counts.get("validation_failed"), Some(&1));
    assert_eq!(counts.get("capability_granted"), Some(&1));
    assert_eq!(counts.get("capability_denied"), Some(&1));
}

#[test]
fn enrichment_event_counts_deterministic_key_ordering() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("ord_comp")).unwrap();
    let name = ComputationName::new("ord_comp").unwrap();
    reg.validate_input(&name, &valid_input(), "t").unwrap();
    let _ = reg.validate_input(&name, &CanonicalValue::Null, "t");

    let keys: Vec<&String> = reg.event_counts().keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn enrichment_multiple_validations_emit_multiple_events() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("multi_ev")).unwrap();
    let name = ComputationName::new("multi_ev").unwrap();
    for i in 0..5 {
        let trace = format!("trace_{i}");
        reg.validate_input(&name, &valid_input(), &trace).unwrap();
    }
    let events = reg.drain_events();
    assert_eq!(events.len(), 5);
    for (i, ev) in events.iter().enumerate() {
        assert_eq!(ev.trace_id, format!("trace_{i}"));
        assert_eq!(ev.outcome, "success");
    }
}

// -- Registry: closure rejection --

#[test]
fn enrichment_reject_closure_empty_reason() {
    let err = RemoteComputationRegistry::reject_closure("");
    assert!(matches!(err, RegistryError::ClosureRejected { .. }));
    if let RegistryError::ClosureRejected { reason } = &err {
        assert!(reason.is_empty());
    }
}

#[test]
fn enrichment_reject_closure_reason_preserved() {
    let msg = "attempted to ship lambda with captured state over network";
    let err = RemoteComputationRegistry::reject_closure(msg);
    if let RegistryError::ClosureRejected { reason } = &err {
        assert_eq!(reason, msg);
    } else {
        panic!("expected ClosureRejected");
    }
}

// -- Registry: lookup edge cases --

#[test]
fn enrichment_lookup_returns_correct_registration_fields() {
    let mut reg = RemoteComputationRegistry::new();
    let registration = ComputationRegistration {
        name: ComputationName::new("detailed_lookup").unwrap(),
        input_schema: test_input_schema(),
        output_schema: test_output_schema(),
        version: SchemaVersion::new(3, 7, 2),
        capability_required: ProfileKind::Full,
        idempotency_class: IdempotencyClass::NaturallyIdempotent,
    };
    reg.register(registration.clone()).unwrap();
    let name = ComputationName::new("detailed_lookup").unwrap();
    let found = reg.lookup(&name).unwrap();
    assert_eq!(found.name.as_str(), "detailed_lookup");
    assert_eq!(found.version, SchemaVersion::new(3, 7, 2));
    assert_eq!(found.capability_required, ProfileKind::Full);
    assert_eq!(
        found.idempotency_class,
        IdempotencyClass::NaturallyIdempotent
    );
    assert_eq!(found.input_schema, test_input_schema());
    assert_eq!(found.output_schema, test_output_schema());
}

#[test]
fn enrichment_lookup_after_hot_register() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::full();
    reg.hot_register(test_registration("hot_lookup"), &profile, "t")
        .unwrap();
    let name = ComputationName::new("hot_lookup").unwrap();
    let found = reg.lookup(&name);
    assert!(found.is_some());
    assert_eq!(found.unwrap().name.as_str(), "hot_lookup");
}

// -- Registry: computation_names --

#[test]
fn enrichment_computation_names_empty_registry() {
    let reg = RemoteComputationRegistry::new();
    assert!(reg.computation_names().is_empty());
}

#[test]
fn enrichment_computation_names_single_entry() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("only_one")).unwrap();
    assert_eq!(reg.computation_names(), vec!["only_one"]);
}

#[test]
fn enrichment_computation_names_deterministic_after_interleaved_hot_and_static() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("zz_static")).unwrap();
    let profile = CapabilityProfile::full();
    reg.hot_register(test_registration("aa_hot"), &profile, "t")
        .unwrap();
    reg.register(test_registration("mm_static")).unwrap();
    assert_eq!(
        reg.computation_names(),
        vec!["aa_hot", "mm_static", "zz_static"]
    );
}

// -- Full lifecycle: extended scenarios --

#[test]
fn enrichment_lifecycle_hot_register_then_validate() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::full();
    reg.hot_register(test_registration("hot_life"), &profile, "t1")
        .unwrap();
    let name = ComputationName::new("hot_life").unwrap();
    let hash = reg.validate_input(&name, &valid_input(), "t2").unwrap();
    assert_eq!(hash.as_bytes().len(), 32);
    let events = reg.drain_events();
    // hot_registration event + schema_validation event
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event, "hot_registration");
    assert_eq!(events[1].event, "schema_validation");
}

#[test]
fn enrichment_lifecycle_multiple_computations_isolated_validation() {
    let mut reg = RemoteComputationRegistry::new();

    let reg_a = ComputationRegistration {
        name: ComputationName::new("comp_a").unwrap(),
        input_schema: ComputationSchema::new("a input", b"a-def", vec!["x".into()]),
        output_schema: test_output_schema(),
        version: SchemaVersion::new(1, 0, 0),
        capability_required: ProfileKind::Remote,
        idempotency_class: IdempotencyClass::RequiresKey,
    };
    let reg_b = ComputationRegistration {
        name: ComputationName::new("comp_b").unwrap(),
        input_schema: ComputationSchema::new("b input", b"b-def", vec!["y".into()]),
        output_schema: test_output_schema(),
        version: SchemaVersion::new(1, 0, 0),
        capability_required: ProfileKind::Remote,
        idempotency_class: IdempotencyClass::NaturallyIdempotent,
    };
    reg.register(reg_a).unwrap();
    reg.register(reg_b).unwrap();

    let name_a = ComputationName::new("comp_a").unwrap();
    let name_b = ComputationName::new("comp_b").unwrap();

    // comp_a expects "x", comp_b expects "y"
    let mut map_a = BTreeMap::new();
    map_a.insert("x".into(), CanonicalValue::String("val".into()));
    let mut map_b = BTreeMap::new();
    map_b.insert("y".into(), CanonicalValue::String("val".into()));

    // Each validates against its own schema
    reg.validate_input(&name_a, &CanonicalValue::Map(map_a.clone()), "t1")
        .unwrap();
    reg.validate_input(&name_b, &CanonicalValue::Map(map_b.clone()), "t2")
        .unwrap();

    // Cross-validation fails
    let err = reg
        .validate_input(&name_a, &CanonicalValue::Map(map_b), "t3")
        .unwrap_err();
    assert!(matches!(err, RegistryError::SchemaValidationFailed { .. }));
}

#[test]
fn enrichment_default_and_new_produce_equivalent_registries() {
    let a = RemoteComputationRegistry::new();
    let b = RemoteComputationRegistry::default();
    assert_eq!(a.len(), b.len());
    assert_eq!(a.is_empty(), b.is_empty());
    assert_eq!(a.computation_names(), b.computation_names());
    assert!(a.event_counts().is_empty());
    assert!(b.event_counts().is_empty());
}

#[test]
fn enrichment_registry_debug_contains_type_name() {
    let reg = RemoteComputationRegistry::new();
    let d = format!("{reg:?}");
    assert!(d.contains("RemoteComputationRegistry"));
}

#[test]
fn enrichment_validation_failed_event_has_empty_input_hash() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("fail_hash")).unwrap();
    let name = ComputationName::new("fail_hash").unwrap();
    let _ = reg.validate_input(&name, &CanonicalValue::Null, "t");
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert!(events[0].input_hash.is_empty());
}

#[test]
fn enrichment_validation_success_event_has_nonempty_input_hash() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("succ_hash")).unwrap();
    let name = ComputationName::new("succ_hash").unwrap();
    reg.validate_input(&name, &valid_input(), "t").unwrap();
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert!(!events[0].input_hash.is_empty());
    // Input hash should be 64 hex chars
    assert_eq!(events[0].input_hash.len(), 64);
    assert!(events[0].input_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_validation_event_component_is_registry() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(test_registration("comp_check")).unwrap();
    let name = ComputationName::new("comp_check").unwrap();
    reg.validate_input(&name, &valid_input(), "t").unwrap();
    let events = reg.drain_events();
    assert_eq!(events[0].component, "registry");
}

#[test]
fn enrichment_validation_event_version_matches_registration() {
    let mut reg = RemoteComputationRegistry::new();
    let mut comp = test_registration("ver_ev");
    comp.version = SchemaVersion::new(4, 5, 6);
    reg.register(comp).unwrap();
    let name = ComputationName::new("ver_ev").unwrap();
    reg.validate_input(&name, &valid_input(), "t").unwrap();
    let events = reg.drain_events();
    assert_eq!(events[0].version, "4.5.6");
}
