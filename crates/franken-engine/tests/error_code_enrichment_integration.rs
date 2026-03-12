#![forbid(unsafe_code)]
//! Enrichment integration tests for `error_code`.
//!
//! Adds Display exactness, Debug distinctness, serde roundtrips, JSON
//! field-name stability, numeric lookup, subsystem mapping, severity
//! classification, and registry completeness beyond the existing 29
//! integration tests.

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

use frankenengine_engine::error_code::{
    ALL_ERROR_CODES, ERROR_CODE_COMPATIBILITY_POLICY, ERROR_CODE_REGISTRY_VERSION, ErrorCodeEntry,
    ErrorCodeRegistry, ErrorSeverity, ErrorSubsystem, FrankenErrorCode, error_code_registry,
};

// ===========================================================================
// 1) FrankenErrorCode — Display (stable_code format)
// ===========================================================================

#[test]
fn franken_error_code_display_format_fe_prefix() {
    for code in ALL_ERROR_CODES {
        let s = code.to_string();
        assert!(
            s.starts_with("FE-"),
            "stable code should start with FE-: {s}"
        );
    }
}

#[test]
fn franken_error_code_display_all_unique() {
    let displays: Vec<String> = ALL_ERROR_CODES.iter().map(|c| c.to_string()).collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), ALL_ERROR_CODES.len());
}

#[test]
fn franken_error_code_display_matches_stable_code() {
    for code in ALL_ERROR_CODES {
        assert_eq!(code.to_string(), code.stable_code());
    }
}

// ===========================================================================
// 2) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_error_severity() {
    let variants = [
        format!("{:?}", ErrorSeverity::Critical),
        format!("{:?}", ErrorSeverity::Error),
        format!("{:?}", ErrorSeverity::Warning),
        format!("{:?}", ErrorSeverity::Info),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_error_subsystem() {
    let variants = [
        format!("{:?}", ErrorSubsystem::SerializationEncoding),
        format!("{:?}", ErrorSubsystem::IdentityAuthentication),
        format!("{:?}", ErrorSubsystem::CapabilityAuthorization),
        format!("{:?}", ErrorSubsystem::CheckpointPolicy),
        format!("{:?}", ErrorSubsystem::Revocation),
        format!("{:?}", ErrorSubsystem::SessionChannel),
        format!("{:?}", ErrorSubsystem::ZoneScope),
        format!("{:?}", ErrorSubsystem::AuditObservability),
        format!("{:?}", ErrorSubsystem::LifecycleMigration),
        format!("{:?}", ErrorSubsystem::Reserved),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 10);
}

#[test]
fn debug_distinct_franken_error_code_all() {
    let variants: Vec<String> = ALL_ERROR_CODES.iter().map(|c| format!("{c:?}")).collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), ALL_ERROR_CODES.len());
}

// ===========================================================================
// 3) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_error_severity_tags() {
    let severities = [
        ErrorSeverity::Critical,
        ErrorSeverity::Error,
        ErrorSeverity::Warning,
        ErrorSeverity::Info,
    ];
    let expected = ["\"critical\"", "\"error\"", "\"warning\"", "\"info\""];
    for (s, exp) in severities.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(json, *exp, "ErrorSeverity serde tag mismatch for {s:?}");
    }
}

#[test]
fn serde_exact_error_subsystem_tags() {
    let subsystems = [
        ErrorSubsystem::SerializationEncoding,
        ErrorSubsystem::IdentityAuthentication,
        ErrorSubsystem::CapabilityAuthorization,
    ];
    let expected = [
        "\"serialization_encoding\"",
        "\"identity_authentication\"",
        "\"capability_authorization\"",
    ];
    for (s, exp) in subsystems.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(json, *exp, "ErrorSubsystem serde tag mismatch for {s:?}");
    }
}

// ===========================================================================
// 4) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_error_code_entry() {
    let entry = FrankenErrorCode::NonCanonicalEncodingError.to_registry_entry();
    let v: serde_json::Value = serde_json::to_value(&entry).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "code",
        "numeric",
        "subsystem",
        "severity",
        "description",
        "operator_action",
        "deprecated",
    ] {
        assert!(obj.contains_key(key), "ErrorCodeEntry missing field: {key}");
    }
}

#[test]
fn json_fields_error_code_registry() {
    let registry = error_code_registry();
    let v: serde_json::Value = serde_json::to_value(&registry).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["version", "compatibility_policy", "entries"] {
        assert!(
            obj.contains_key(key),
            "ErrorCodeRegistry missing field: {key}"
        );
    }
}

// ===========================================================================
// 5) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(ERROR_CODE_REGISTRY_VERSION, 1);
    assert!(ERROR_CODE_COMPATIBILITY_POLICY.contains("append-only"));
}

#[test]
fn all_error_codes_count() {
    assert_eq!(ALL_ERROR_CODES.len(), 42);
}

// ===========================================================================
// 6) Numeric uniqueness
// ===========================================================================

#[test]
fn all_numeric_codes_unique() {
    let numerics: Vec<u16> = ALL_ERROR_CODES.iter().map(|c| c.numeric()).collect();
    let unique: BTreeSet<_> = numerics.iter().collect();
    assert_eq!(unique.len(), ALL_ERROR_CODES.len());
}

// ===========================================================================
// 7) Descriptions uniqueness
// ===========================================================================

#[test]
fn all_descriptions_unique() {
    let descs: Vec<&str> = ALL_ERROR_CODES.iter().map(|c| c.description()).collect();
    let unique: BTreeSet<_> = descs.iter().collect();
    assert_eq!(unique.len(), ALL_ERROR_CODES.len());
}

#[test]
fn all_descriptions_non_empty() {
    for code in ALL_ERROR_CODES {
        assert!(
            !code.description().is_empty(),
            "description empty for {code:?}"
        );
    }
}

// ===========================================================================
// 8) Operator actions uniqueness
// ===========================================================================

#[test]
fn all_operator_actions_non_empty() {
    for code in ALL_ERROR_CODES {
        assert!(
            !code.operator_action().is_empty(),
            "operator_action empty for {code:?}"
        );
    }
}

// ===========================================================================
// 9) Subsystem mapping consistency
// ===========================================================================

#[test]
fn all_codes_in_their_subsystem_range() {
    for code in ALL_ERROR_CODES {
        let sub = code.subsystem();
        assert!(
            sub.includes(code.numeric()),
            "{code:?} numeric {} not in subsystem {:?} range {:?}",
            code.numeric(),
            sub,
            sub.range()
        );
    }
}

#[test]
fn subsystem_ranges_non_overlapping() {
    let subsystems = [
        ErrorSubsystem::SerializationEncoding,
        ErrorSubsystem::IdentityAuthentication,
        ErrorSubsystem::CapabilityAuthorization,
        ErrorSubsystem::CheckpointPolicy,
        ErrorSubsystem::Revocation,
        ErrorSubsystem::SessionChannel,
        ErrorSubsystem::ZoneScope,
        ErrorSubsystem::AuditObservability,
        ErrorSubsystem::LifecycleMigration,
        ErrorSubsystem::Reserved,
    ];
    for i in 0..subsystems.len() {
        for j in (i + 1)..subsystems.len() {
            let (s1, e1) = subsystems[i].range();
            let (s2, e2) = subsystems[j].range();
            assert!(
                e1 < s2 || e2 < s1,
                "subsystems {:?} and {:?} overlap: ({s1},{e1}) vs ({s2},{e2})",
                subsystems[i],
                subsystems[j]
            );
        }
    }
}

// ===========================================================================
// 10) Severity classification
// ===========================================================================

#[test]
fn critical_severity_codes() {
    let critical_codes = [
        FrankenErrorCode::PolicyCheckpointValidationError,
        FrankenErrorCode::CheckpointFrontierEnforcementError,
        FrankenErrorCode::ForkDetectionError,
        FrankenErrorCode::RevocationChainIntegrityError,
        FrankenErrorCode::EpochMonotonicityViolation,
    ];
    for code in &critical_codes {
        assert_eq!(
            code.severity(),
            ErrorSeverity::Critical,
            "{code:?} should be Critical"
        );
    }
}

#[test]
fn non_critical_codes_are_error_severity() {
    let critical_numerics: BTreeSet<u16> = [3000, 3001, 3002, 4000, 8000].iter().copied().collect();
    for code in ALL_ERROR_CODES {
        if !critical_numerics.contains(&code.numeric()) {
            assert_eq!(
                code.severity(),
                ErrorSeverity::Error,
                "{code:?} should be Error severity"
            );
        }
    }
}

// ===========================================================================
// 11) from_numeric lookup
// ===========================================================================

#[test]
fn from_numeric_roundtrips_all_codes() {
    for code in ALL_ERROR_CODES {
        let found = FrankenErrorCode::from_numeric(code.numeric());
        assert_eq!(
            found,
            Some(*code),
            "from_numeric({}) failed for {code:?}",
            code.numeric()
        );
    }
}

#[test]
fn from_numeric_returns_none_for_unassigned() {
    assert!(FrankenErrorCode::from_numeric(999).is_none());
    assert!(FrankenErrorCode::from_numeric(9999).is_none());
    assert!(FrankenErrorCode::from_numeric(u16::MAX).is_none());
}

// ===========================================================================
// 12) deprecated flag
// ===========================================================================

#[test]
fn no_codes_deprecated() {
    for code in ALL_ERROR_CODES {
        assert!(!code.deprecated(), "{code:?} should not be deprecated");
    }
}

// ===========================================================================
// 13) Registry construction
// ===========================================================================

#[test]
fn registry_version_matches_constant() {
    let registry = error_code_registry();
    assert_eq!(registry.version, ERROR_CODE_REGISTRY_VERSION);
}

#[test]
fn registry_policy_matches_constant() {
    let registry = error_code_registry();
    assert_eq!(
        registry.compatibility_policy,
        ERROR_CODE_COMPATIBILITY_POLICY
    );
}

#[test]
fn registry_has_all_codes() {
    let registry = error_code_registry();
    assert_eq!(registry.entries.len(), ALL_ERROR_CODES.len());
}

#[test]
fn registry_entries_match_codes() {
    let registry = error_code_registry();
    for (entry, code) in registry.entries.iter().zip(ALL_ERROR_CODES.iter()) {
        assert_eq!(entry.numeric, code.numeric());
        assert_eq!(entry.code, code.stable_code());
        assert_eq!(entry.subsystem, code.subsystem());
        assert_eq!(entry.severity, code.severity());
    }
}

// ===========================================================================
// 14) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_error_severity() {
    for s in [
        ErrorSeverity::Critical,
        ErrorSeverity::Error,
        ErrorSeverity::Warning,
        ErrorSeverity::Info,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ErrorSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_error_subsystem_all() {
    let subsystems = [
        ErrorSubsystem::SerializationEncoding,
        ErrorSubsystem::IdentityAuthentication,
        ErrorSubsystem::CapabilityAuthorization,
        ErrorSubsystem::CheckpointPolicy,
        ErrorSubsystem::Revocation,
        ErrorSubsystem::SessionChannel,
        ErrorSubsystem::ZoneScope,
        ErrorSubsystem::AuditObservability,
        ErrorSubsystem::LifecycleMigration,
        ErrorSubsystem::Reserved,
    ];
    for s in &subsystems {
        let json = serde_json::to_string(s).unwrap();
        let rt: ErrorSubsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, rt);
    }
}

#[test]
fn serde_roundtrip_franken_error_code_all() {
    for code in ALL_ERROR_CODES {
        let json = serde_json::to_string(code).unwrap();
        let rt: FrankenErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, rt);
    }
}

#[test]
fn serde_roundtrip_error_code_entry() {
    let entry = FrankenErrorCode::NonCanonicalEncodingError.to_registry_entry();
    let json = serde_json::to_string(&entry).unwrap();
    let rt: ErrorCodeEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, rt);
}

#[test]
fn serde_roundtrip_error_code_registry() {
    let registry = error_code_registry();
    let json = serde_json::to_string(&registry).unwrap();
    let rt: ErrorCodeRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(registry, rt);
}

// ===========================================================================
// 15) Specific numeric values
// ===========================================================================

#[test]
fn specific_numeric_values() {
    assert_eq!(FrankenErrorCode::NonCanonicalEncodingError.numeric(), 1);
    assert_eq!(FrankenErrorCode::DeterministicSerdeError.numeric(), 2);
    assert_eq!(FrankenErrorCode::EngineObjectIdError.numeric(), 1000);
    assert_eq!(FrankenErrorCode::CapabilityDeniedError.numeric(), 2000);
    assert_eq!(
        FrankenErrorCode::PolicyCheckpointValidationError.numeric(),
        3000
    );
    assert_eq!(
        FrankenErrorCode::RevocationChainIntegrityError.numeric(),
        4000
    );
    assert_eq!(FrankenErrorCode::LeaseLifecycleError.numeric(), 5000);
    assert_eq!(
        FrankenErrorCode::AllocationDomainBudgetError.numeric(),
        6000
    );
    assert_eq!(FrankenErrorCode::EvidenceContractError.numeric(), 7000);
    assert_eq!(FrankenErrorCode::EpochMonotonicityViolation.numeric(), 8000);
}

// ===========================================================================
// 16) stable_code format
// ===========================================================================

#[test]
fn stable_code_format_4_digit_padded() {
    let code = FrankenErrorCode::NonCanonicalEncodingError;
    assert_eq!(code.stable_code(), "FE-0001");

    let code = FrankenErrorCode::EngineObjectIdError;
    assert_eq!(code.stable_code(), "FE-1000");
}

// ===========================================================================
// 17) Clone trait preserves equality
// ===========================================================================

#[test]
fn clone_franken_error_code_preserves_equality() {
    for code in ALL_ERROR_CODES {
        let cloned = code.clone();
        assert_eq!(*code, cloned, "Clone should preserve equality for {code:?}");
        assert_eq!(code.numeric(), cloned.numeric());
        assert_eq!(code.stable_code(), cloned.stable_code());
    }
}

#[test]
fn clone_error_code_entry_preserves_all_fields() {
    for code in ALL_ERROR_CODES {
        let entry = code.to_registry_entry();
        let cloned = entry.clone();
        assert_eq!(entry, cloned, "ErrorCodeEntry Clone mismatch for {code:?}");
        assert_eq!(entry.code, cloned.code);
        assert_eq!(entry.numeric, cloned.numeric);
        assert_eq!(entry.subsystem, cloned.subsystem);
        assert_eq!(entry.severity, cloned.severity);
        assert_eq!(entry.description, cloned.description);
        assert_eq!(entry.operator_action, cloned.operator_action);
        assert_eq!(entry.deprecated, cloned.deprecated);
    }
}

#[test]
fn clone_error_code_registry_preserves_equality() {
    let registry = error_code_registry();
    let cloned = registry.clone();
    assert_eq!(registry, cloned);
    assert_eq!(registry.version, cloned.version);
    assert_eq!(registry.compatibility_policy, cloned.compatibility_policy);
    assert_eq!(registry.entries.len(), cloned.entries.len());
}

// ===========================================================================
// 18) Description and operator_action end with period
// ===========================================================================

#[test]
fn all_descriptions_end_with_period() {
    for code in ALL_ERROR_CODES {
        let desc = code.description();
        assert!(
            desc.ends_with('.'),
            "{code:?} description does not end with period: {desc}"
        );
    }
}

#[test]
fn all_operator_actions_end_with_period() {
    for code in ALL_ERROR_CODES {
        let action = code.operator_action();
        assert!(
            action.ends_with('.'),
            "{code:?} operator_action does not end with period: {action}"
        );
    }
}

// ===========================================================================
// 19) JSON serialization determinism
// ===========================================================================

#[test]
fn registry_json_serialization_is_deterministic() {
    let registry = error_code_registry();
    let json1 = serde_json::to_string(&registry).unwrap();
    let json2 = serde_json::to_string(&registry).unwrap();
    assert_eq!(
        json1, json2,
        "Registry JSON serialization should be deterministic"
    );
}

#[test]
fn registry_pretty_json_roundtrips() {
    let registry = error_code_registry();
    let pretty = serde_json::to_string_pretty(&registry).unwrap();
    let rt: ErrorCodeRegistry = serde_json::from_str(&pretty).unwrap();
    assert_eq!(
        registry, rt,
        "Pretty JSON roundtrip should preserve registry"
    );
}

// ===========================================================================
// 20) ALL_ERROR_CODES monotonically sorted by numeric
// ===========================================================================

#[test]
fn all_error_codes_sorted_ascending_by_numeric() {
    for pair in ALL_ERROR_CODES.windows(2) {
        assert!(
            pair[0].numeric() < pair[1].numeric(),
            "ALL_ERROR_CODES not ascending: {} >= {}",
            pair[0].numeric(),
            pair[1].numeric()
        );
    }
}

// ===========================================================================
// 21) stable_code length invariant
// ===========================================================================

#[test]
fn stable_code_length_always_seven() {
    for code in ALL_ERROR_CODES {
        let stable = code.stable_code();
        assert_eq!(
            stable.len(),
            7,
            "stable_code for {code:?} has unexpected length: {stable}"
        );
    }
}

// ===========================================================================
// 22) Serde rejection of invalid inputs
// ===========================================================================

#[test]
fn serde_rejects_invalid_severity_string() {
    let result: Result<ErrorSeverity, _> = serde_json::from_str("\"panic\"");
    assert!(
        result.is_err(),
        "Deserializing invalid severity should fail"
    );
}

#[test]
fn serde_rejects_invalid_subsystem_string() {
    let result: Result<ErrorSubsystem, _> = serde_json::from_str("\"networking\"");
    assert!(
        result.is_err(),
        "Deserializing invalid subsystem should fail"
    );
}

// ===========================================================================
// 23) Per-subsystem code count
// ===========================================================================

#[test]
fn each_subsystem_has_at_least_one_assigned_code() {
    let subsystems_with_codes = [
        ErrorSubsystem::SerializationEncoding,
        ErrorSubsystem::IdentityAuthentication,
        ErrorSubsystem::CapabilityAuthorization,
        ErrorSubsystem::CheckpointPolicy,
        ErrorSubsystem::Revocation,
        ErrorSubsystem::SessionChannel,
        ErrorSubsystem::ZoneScope,
        ErrorSubsystem::AuditObservability,
        ErrorSubsystem::LifecycleMigration,
    ];
    for sub in &subsystems_with_codes {
        let count = ALL_ERROR_CODES
            .iter()
            .filter(|c| c.subsystem() == *sub)
            .count();
        assert!(count >= 1, "Subsystem {sub:?} has no assigned error codes");
    }
}

// ===========================================================================
// 24) Hash determinism across all codes
// ===========================================================================

#[test]
fn hash_determinism_all_codes_produce_consistent_hashes() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    for code in ALL_ERROR_CODES {
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        code.hash(&mut h1);
        code.hash(&mut h2);
        assert_eq!(
            h1.finish(),
            h2.finish(),
            "Hash should be deterministic for {code:?}"
        );
    }
}

#[test]
fn hash_distinct_for_different_codes() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hashes = BTreeSet::new();
    for code in ALL_ERROR_CODES {
        let mut hasher = DefaultHasher::new();
        code.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    // All 42 codes should produce distinct hashes (probabilistically guaranteed)
    assert_eq!(
        hashes.len(),
        ALL_ERROR_CODES.len(),
        "All error codes should produce distinct hashes"
    );
}
