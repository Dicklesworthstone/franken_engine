//! Enrichment integration tests (batch 2) for the `remote_computation_registry` module.
//!
//! Covers lifecycle workflows, cross-computation determinism, event counters,
//! version negotiation matrix, and schema validation edge cases.

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
    clippy::identity_op
)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::capability::{CapabilityProfile, ProfileKind};
use frankenengine_engine::control_plane::SchemaVersion;
use frankenengine_engine::deterministic_serde::CanonicalValue;
use frankenengine_engine::remote_computation_registry::{
    ComputationName, ComputationRegistration, ComputationSchema, IdempotencyClass, RegistryError,
    RemoteComputationRegistry, SchemaVersionExt, VersionNegotiationResult,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_schema(desc: &str, def: &[u8], fields: Vec<&str>) -> ComputationSchema {
    ComputationSchema::new(desc, def, fields.into_iter().map(String::from).collect())
}

fn make_registration(name: &str) -> ComputationRegistration {
    ComputationRegistration {
        name: ComputationName::new(name).unwrap(),
        input_schema: make_schema("input", b"in-def-v1", vec!["alpha", "beta"]),
        output_schema: make_schema("output", b"out-def-v1", vec!["result"]),
        version: SchemaVersion::new(1, 0, 0),
        capability_required: ProfileKind::Remote,
        idempotency_class: IdempotencyClass::RequiresKey,
    }
}

fn make_registration_with_version(name: &str, major: u32, minor: u32) -> ComputationRegistration {
    ComputationRegistration {
        name: ComputationName::new(name).unwrap(),
        input_schema: make_schema("input", b"in-def-v1", vec!["alpha", "beta"]),
        output_schema: make_schema("output", b"out-def-v1", vec!["result"]),
        version: SchemaVersion::new(major, minor, 0),
        capability_required: ProfileKind::Remote,
        idempotency_class: IdempotencyClass::NaturallyIdempotent,
    }
}

fn valid_map_input() -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert("alpha".to_string(), CanonicalValue::String("a".to_string()));
    map.insert("beta".to_string(), CanonicalValue::String("b".to_string()));
    CanonicalValue::Map(map)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_and_lookup_round_trip() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("lookup_test")).unwrap();
    let name = ComputationName::new("lookup_test").unwrap();
    let found = reg.lookup(&name).unwrap();
    assert_eq!(found.name.as_str(), "lookup_test");
    assert_eq!(found.capability_required, ProfileKind::Remote);
    assert_eq!(found.idempotency_class, IdempotencyClass::RequiresKey);
}

#[test]
fn enrichment_register_ten_computations_deterministic_order() {
    let mut reg = RemoteComputationRegistry::new();
    let names = [
        "zulu", "yankee", "xray", "whiskey", "victor",
        "uniform", "tango", "sierra", "romeo", "papa",
    ];
    for n in &names {
        reg.register(make_registration(n)).unwrap();
    }
    assert_eq!(reg.len(), 10);
    let listed = reg.computation_names();
    let mut expected = names.to_vec();
    expected.sort_unstable();
    assert_eq!(listed, expected);
}

#[test]
fn enrichment_duplicate_across_different_schemas_still_rejected() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("dup_comp")).unwrap();
    let mut dup = make_registration("dup_comp");
    dup.input_schema = make_schema("different", b"different-def", vec!["x"]);
    assert!(matches!(
        reg.register(dup),
        Err(RegistryError::DuplicateRegistration { .. })
    ));
}

#[test]
fn enrichment_validate_input_returns_consistent_hash() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("hash_comp")).unwrap();
    let name = ComputationName::new("hash_comp").unwrap();
    let h1 = reg.validate_input(&name, &valid_map_input(), "t1").unwrap();
    let h2 = reg.validate_input(&name, &valid_map_input(), "t2").unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_validate_input_different_values_different_hashes() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("diff_hash")).unwrap();
    let name = ComputationName::new("diff_hash").unwrap();

    let mut map1 = BTreeMap::new();
    map1.insert("alpha".to_string(), CanonicalValue::String("val1".to_string()));
    map1.insert("beta".to_string(), CanonicalValue::String("val2".to_string()));

    let mut map2 = BTreeMap::new();
    map2.insert("alpha".to_string(), CanonicalValue::String("val3".to_string()));
    map2.insert("beta".to_string(), CanonicalValue::String("val4".to_string()));

    let h1 = reg.validate_input(&name, &CanonicalValue::Map(map1), "t1").unwrap();
    let h2 = reg.validate_input(&name, &CanonicalValue::Map(map2), "t2").unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_validation_failure_does_not_increment_success_counter() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("fail_cnt")).unwrap();
    let name = ComputationName::new("fail_cnt").unwrap();
    let _ = reg.validate_input(&name, &CanonicalValue::Null, "t");
    assert_eq!(reg.event_counts().get("validation_success"), None);
    assert_eq!(reg.event_counts().get("validation_failed"), Some(&1));
}

#[test]
fn enrichment_multiple_validation_failures_accumulate() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("multi_fail")).unwrap();
    let name = ComputationName::new("multi_fail").unwrap();
    for _ in 0..5 {
        let _ = reg.validate_input(&name, &CanonicalValue::Null, "t");
    }
    assert_eq!(reg.event_counts().get("validation_failed"), Some(&5));
}

#[test]
fn enrichment_capability_check_all_profile_kinds() {
    let profiles = [
        (ProfileKind::Full, CapabilityProfile::full()),
        (ProfileKind::EngineCore, CapabilityProfile::engine_core()),
        (ProfileKind::Policy, CapabilityProfile::policy()),
        (ProfileKind::Remote, CapabilityProfile::remote()),
        (ProfileKind::ComputeOnly, CapabilityProfile::compute_only()),
    ];
    for (kind, profile) in &profiles {
        let mut reg = RemoteComputationRegistry::new();
        let mut comp = make_registration("cap_test");
        comp.capability_required = *kind;
        reg.register(comp).unwrap();
        let name = ComputationName::new("cap_test").unwrap();
        let result = reg.check_capability(&name, profile, "t");
        assert!(
            result.is_ok(),
            "profile kind {:?} should subsume its own requirement",
            kind
        );
    }
}

#[test]
fn enrichment_capability_compute_only_denied_for_remote() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("cap_deny")).unwrap();
    let name = ComputationName::new("cap_deny").unwrap();
    let profile = CapabilityProfile::compute_only();
    let err = reg.check_capability(&name, &profile, "t").unwrap_err();
    assert!(matches!(err, RegistryError::CapabilityDenied { .. }));
}

#[test]
fn enrichment_version_negotiation_matrix() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration_with_version("vneg", 2, 3)).unwrap();
    let name = ComputationName::new("vneg").unwrap();

    // same major, higher minor => compatible
    let r = reg.negotiate_version(&name, SchemaVersion::new(2, 5, 0)).unwrap();
    assert!(r.compatible);

    // same major, same minor => compatible
    let r = reg.negotiate_version(&name, SchemaVersion::new(2, 3, 0)).unwrap();
    assert!(r.compatible);

    // same major, lower minor => incompatible
    let r = reg.negotiate_version(&name, SchemaVersion::new(2, 1, 0)).unwrap();
    assert!(!r.compatible);

    // different major => incompatible
    let r = reg.negotiate_version(&name, SchemaVersion::new(3, 0, 0)).unwrap();
    assert!(!r.compatible);
}

#[test]
fn enrichment_version_negotiation_result_fields() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration_with_version("vfields", 1, 2)).unwrap();
    let name = ComputationName::new("vfields").unwrap();
    let r = reg.negotiate_version(&name, SchemaVersion::new(1, 5, 0)).unwrap();
    assert_eq!(r.computation_name.as_str(), "vfields");
    assert_eq!(r.local_version, SchemaVersion::new(1, 2, 0));
    assert_eq!(r.remote_version, SchemaVersion::new(1, 5, 0));
}

#[test]
fn enrichment_reject_closure_preserves_reason_string() {
    let reasons = [
        "closure with upvalues",
        "opaque function pointer",
        "untyped blob payload",
    ];
    for reason in &reasons {
        let err = RemoteComputationRegistry::reject_closure(reason);
        if let RegistryError::ClosureRejected { reason: r } = &err {
            assert_eq!(r, reason);
        } else {
            panic!("expected ClosureRejected");
        }
    }
}

#[test]
fn enrichment_compute_input_hash_domain_separation() {
    let name_a = ComputationName::new("comp_a").unwrap();
    let name_b = ComputationName::new("comp_b").unwrap();
    let input = valid_map_input();
    let h_a = RemoteComputationRegistry::compute_input_hash(&name_a, &input);
    let h_b = RemoteComputationRegistry::compute_input_hash(&name_b, &input);
    assert_ne!(h_a, h_b, "different computation names must produce different hashes");
}

#[test]
fn enrichment_compute_input_hash_32_bytes() {
    let name = ComputationName::new("bytes_check").unwrap();
    let hash = RemoteComputationRegistry::compute_input_hash(&name, &valid_map_input());
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn enrichment_hot_register_with_full_profile() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::full();
    reg.hot_register(make_registration("hot_full"), &profile, "trace-hot")
        .unwrap();
    assert_eq!(reg.len(), 1);
    let events = reg.drain_events();
    assert_eq!(events[0].event, "hot_registration");
}

#[test]
fn enrichment_hot_register_events_include_trace_id() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::policy();
    reg.hot_register(make_registration("hot_trace"), &profile, "my_trace_id")
        .unwrap();
    let events = reg.drain_events();
    assert_eq!(events[0].trace_id, "my_trace_id");
}

#[test]
fn enrichment_drain_events_idempotent() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("drain_test")).unwrap();
    let name = ComputationName::new("drain_test").unwrap();
    reg.validate_input(&name, &valid_map_input(), "t").unwrap();
    assert!(!reg.drain_events().is_empty());
    assert!(reg.drain_events().is_empty());
    assert!(reg.drain_events().is_empty());
}

#[test]
fn enrichment_event_counts_accumulate_registrations() {
    let mut reg = RemoteComputationRegistry::new();
    for i in 0..5u32 {
        reg.register(make_registration(&format!("reg_{i}"))).unwrap();
    }
    assert_eq!(reg.event_counts().get("registration"), Some(&5));
}

#[test]
fn enrichment_schema_version_ext_compatible_same_major_higher_minor() {
    let v = SchemaVersion::new(3, 2, 0);
    assert!(v.is_compatible_with(&SchemaVersion::new(3, 5, 0)));
}

#[test]
fn enrichment_schema_version_ext_incompatible_lower_minor() {
    let v = SchemaVersion::new(3, 5, 0);
    assert!(!v.is_compatible_with(&SchemaVersion::new(3, 2, 0)));
}

#[test]
fn enrichment_computation_name_ordering() {
    let a = ComputationName::new("alpha").unwrap();
    let b = ComputationName::new("beta").unwrap();
    assert!(a < b);
}

#[test]
fn enrichment_computation_name_equality() {
    let a = ComputationName::new("same").unwrap();
    let b = ComputationName::new("same").unwrap();
    assert_eq!(a, b);
}

#[test]
fn enrichment_computation_name_rejects_hyphen() {
    assert!(matches!(
        ComputationName::new("has-hyphen"),
        Err(RegistryError::InvalidComputationName { .. })
    ));
}

#[test]
fn enrichment_computation_name_rejects_unicode() {
    assert!(matches!(
        ComputationName::new("caf\u{00e9}"),
        Err(RegistryError::InvalidComputationName { .. })
    ));
}

#[test]
fn enrichment_registry_error_display_all_variants_nonempty() {
    let errors: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName { name: "x".into(), reason: "r".into() },
        RegistryError::DuplicateRegistration { name: "x".into() },
        RegistryError::ComputationNotFound { name: "x".into() },
        RegistryError::SchemaValidationFailed { computation_name: "x".into(), reason: "r".into() },
        RegistryError::CapabilityDenied { computation_name: "x".into(), required: ProfileKind::Full, held: ProfileKind::ComputeOnly },
        RegistryError::VersionIncompatible { computation_name: "x".into(), registered: SchemaVersion::new(1,0,0), requested: SchemaVersion::new(2,0,0) },
        RegistryError::ClosureRejected { reason: "r".into() },
        RegistryError::HotRegistrationDenied { reason: "r".into() },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len(), "all error variants must have distinct display");
}

#[test]
fn enrichment_registry_error_serde_round_trip_all_variants() {
    let errors: Vec<RegistryError> = vec![
        RegistryError::InvalidComputationName { name: "n".into(), reason: "r".into() },
        RegistryError::DuplicateRegistration { name: "n".into() },
        RegistryError::ComputationNotFound { name: "n".into() },
        RegistryError::SchemaValidationFailed { computation_name: "n".into(), reason: "r".into() },
        RegistryError::CapabilityDenied { computation_name: "n".into(), required: ProfileKind::EngineCore, held: ProfileKind::Remote },
        RegistryError::VersionIncompatible { computation_name: "n".into(), registered: SchemaVersion::new(1,0,0), requested: SchemaVersion::new(2,0,0) },
        RegistryError::ClosureRejected { reason: "r".into() },
        RegistryError::HotRegistrationDenied { reason: "r".into() },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: RegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn enrichment_version_negotiation_result_serde_round_trip() {
    let result = VersionNegotiationResult {
        computation_name: ComputationName::new("serde_vnr").unwrap(),
        compatible: false,
        local_version: SchemaVersion::new(3, 1, 0),
        remote_version: SchemaVersion::new(2, 0, 0),
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_full_lifecycle_register_validate_capability_negotiate() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("lifecycle")).unwrap();
    let name = ComputationName::new("lifecycle").unwrap();

    // capability check
    let profile = CapabilityProfile::full();
    reg.check_capability(&name, &profile, "t-cap").unwrap();

    // validate input
    let hash = reg.validate_input(&name, &valid_map_input(), "t-val").unwrap();
    assert_eq!(hash.as_bytes().len(), 32);

    // negotiate version
    let neg = reg.negotiate_version(&name, SchemaVersion::new(1, 1, 0)).unwrap();
    assert!(neg.compatible);

    // compute idempotency hash
    let idem = RemoteComputationRegistry::compute_input_hash(&name, &valid_map_input());
    assert_eq!(idem.as_bytes().len(), 32);

    // verify events accumulated (validation emits 1 event, capability success does not)
    let events = reg.drain_events();
    assert!(events.len() >= 1);
}

#[test]
fn enrichment_empty_registry_has_no_names() {
    let reg = RemoteComputationRegistry::new();
    assert!(reg.computation_names().is_empty());
}

#[test]
fn enrichment_default_registry_identical_to_new() {
    let new_reg = RemoteComputationRegistry::new();
    let default_reg = RemoteComputationRegistry::default();
    assert_eq!(new_reg.len(), default_reg.len());
    assert!(new_reg.is_empty());
    assert!(default_reg.is_empty());
}

#[test]
fn enrichment_validate_input_emits_event_with_correct_component() {
    let mut reg = RemoteComputationRegistry::new();
    reg.register(make_registration("comp_ev")).unwrap();
    let name = ComputationName::new("comp_ev").unwrap();
    reg.validate_input(&name, &valid_map_input(), "t-comp").unwrap();
    let events = reg.drain_events();
    assert_eq!(events[0].component, "registry");
}

#[test]
fn enrichment_idempotency_class_display_values() {
    assert_eq!(IdempotencyClass::NaturallyIdempotent.to_string(), "naturally_idempotent");
    assert_eq!(IdempotencyClass::RequiresKey.to_string(), "requires_key");
}

#[test]
fn enrichment_computation_schema_hash_differs_for_different_definitions() {
    let s1 = ComputationSchema::new("test", b"definition-a", vec!["x".to_string()]);
    let s2 = ComputationSchema::new("test", b"definition-b", vec!["x".to_string()]);
    assert_ne!(s1.schema_hash, s2.schema_hash);
}

#[test]
fn enrichment_hot_register_denied_event_has_denied_outcome() {
    let mut reg = RemoteComputationRegistry::new();
    let profile = CapabilityProfile::compute_only();
    let _ = reg.hot_register(make_registration("denied_hot"), &profile, "trace-x");
    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "denied");
    assert_eq!(events[0].event, "hot_registration_denied");
    assert_eq!(events[0].trace_id, "trace-x");
}
