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
