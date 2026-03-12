#![forbid(unsafe_code)]
//! Integration tests for the `error_code` module.
//!
//! Exercises error code enumeration, subsystem ranges, severity levels,
//! registry construction, numeric lookups, stable codes, operator actions,
//! and serde round-trips from outside the crate boundary.

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

use frankenengine_engine::error_code::{
    ALL_ERROR_CODES, ERROR_CODE_COMPATIBILITY_POLICY, ERROR_CODE_REGISTRY_VERSION, ErrorCodeEntry,
    ErrorCodeRegistry, ErrorSeverity, ErrorSubsystem, FrankenErrorCode, error_code_registry,
};

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn registry_version_is_one() {
    assert_eq!(ERROR_CODE_REGISTRY_VERSION, 1);
}

#[test]
fn compatibility_policy_nonempty() {
    assert!(!ERROR_CODE_COMPATIBILITY_POLICY.is_empty());
    assert!(ERROR_CODE_COMPATIBILITY_POLICY.contains("append-only"));
}

#[test]
fn all_error_codes_nonempty() {
    assert!(!ALL_ERROR_CODES.is_empty());
    // Should have 42 codes per the module doc
    assert_eq!(ALL_ERROR_CODES.len(), 42);
}

// ===========================================================================
// 2. ErrorSeverity
// ===========================================================================

#[test]
fn error_severity_serde_round_trip() {
    for sev in [
        ErrorSeverity::Critical,
        ErrorSeverity::Error,
        ErrorSeverity::Warning,
        ErrorSeverity::Info,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: ErrorSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sev);
    }
}

// ===========================================================================
// 3. ErrorSubsystem
// ===========================================================================

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
    // Check that each subsystem's range is non-empty and doesn't overlap
    for (i, s1) in subsystems.iter().enumerate() {
        let (lo1, hi1) = s1.range();
        assert!(lo1 <= hi1, "subsystem {s1:?} has empty range");
        for s2 in &subsystems[i + 1..] {
            let (lo2, hi2) = s2.range();
            assert!(
                hi1 < lo2 || hi2 < lo1,
                "subsystems {s1:?} and {s2:?} overlap"
            );
        }
    }
}

#[test]
fn subsystem_includes_own_range() {
    let subsys = ErrorSubsystem::CapabilityAuthorization;
    let (lo, hi) = subsys.range();
    assert!(subsys.includes(lo));
    assert!(subsys.includes(hi));
    // Outside the range
    if lo > 0 {
        assert!(!subsys.includes(lo - 1));
    }
    assert!(!subsys.includes(hi + 1));
}

#[test]
fn subsystem_serde_round_trip() {
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
        let back: ErrorSubsystem = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, s);
    }
}

// ===========================================================================
// 4. FrankenErrorCode — numeric and stable code
// ===========================================================================

#[test]
fn error_code_numeric_round_trip() {
    for &code in ALL_ERROR_CODES {
        let numeric = code.numeric();
        let recovered = FrankenErrorCode::from_numeric(numeric);
        assert_eq!(
            recovered,
            Some(code),
            "numeric round-trip failed for {code:?}"
        );
    }
}

#[test]
fn error_code_stable_code_format() {
    for &code in ALL_ERROR_CODES {
        let stable = code.stable_code();
        assert!(
            stable.starts_with("FE-"),
            "stable code {stable} doesn't start with FE-"
        );
        let numeric_part = &stable[3..];
        let parsed: u16 = numeric_part.parse().unwrap();
        assert_eq!(parsed, code.numeric());
    }
}

#[test]
fn error_code_display_matches_stable_code() {
    for &code in ALL_ERROR_CODES {
        assert_eq!(code.to_string(), code.stable_code());
    }
}

#[test]
fn error_code_from_numeric_unknown_returns_none() {
    // Pick values that are very unlikely to be assigned
    assert!(FrankenErrorCode::from_numeric(9999).is_none());
    assert!(FrankenErrorCode::from_numeric(65535).is_none());
}

// ===========================================================================
// 5. FrankenErrorCode — subsystem mapping
// ===========================================================================

#[test]
fn error_code_subsystem_consistent_with_numeric() {
    for &code in ALL_ERROR_CODES {
        let subsys = code.subsystem();
        assert!(
            subsys.includes(code.numeric()),
            "code {code:?} numeric {} not in subsystem {subsys:?} range",
            code.numeric()
        );
    }
}

// ===========================================================================
// 6. FrankenErrorCode — severity
// ===========================================================================

#[test]
fn critical_codes_are_critical() {
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
fn non_critical_codes_are_error() {
    // Most codes are Error severity
    let non_critical = FrankenErrorCode::CapabilityDeniedError;
    assert_eq!(non_critical.severity(), ErrorSeverity::Error);
}

// ===========================================================================
// 7. FrankenErrorCode — description and operator_action
// ===========================================================================

#[test]
fn all_codes_have_description() {
    for &code in ALL_ERROR_CODES {
        assert!(
            !code.description().is_empty(),
            "code {code:?} has empty description"
        );
    }
}

#[test]
fn all_codes_have_operator_action() {
    for &code in ALL_ERROR_CODES {
        assert!(
            !code.operator_action().is_empty(),
            "code {code:?} has empty operator_action"
        );
    }
}

// ===========================================================================
// 8. FrankenErrorCode — deprecation
// ===========================================================================

#[test]
fn no_codes_deprecated_in_v1() {
    for &code in ALL_ERROR_CODES {
        assert!(
            !code.deprecated(),
            "code {code:?} is deprecated but we're in v1"
        );
    }
}

// ===========================================================================
// 9. FrankenErrorCode — serde
// ===========================================================================

#[test]
fn error_code_serde_round_trip() {
    for &code in ALL_ERROR_CODES {
        let json = serde_json::to_string(&code).unwrap();
        let back: FrankenErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, code);
    }
}

// ===========================================================================
// 10. ErrorCodeEntry
// ===========================================================================

#[test]
fn to_registry_entry_fields_correct() {
    let code = FrankenErrorCode::CapabilityDeniedError;
    let entry = code.to_registry_entry();
    assert_eq!(entry.code, code.stable_code());
    assert_eq!(entry.numeric, code.numeric());
    assert_eq!(entry.subsystem, code.subsystem());
    assert_eq!(entry.severity, code.severity());
    assert_eq!(entry.description, code.description());
    assert_eq!(entry.operator_action, code.operator_action());
    assert_eq!(entry.deprecated, code.deprecated());
}

#[test]
fn error_code_entry_serde_round_trip() {
    let entry = FrankenErrorCode::ForkDetectionError.to_registry_entry();
    let json = serde_json::to_string(&entry).unwrap();
    let back: ErrorCodeEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 11. ErrorCodeRegistry
// ===========================================================================

#[test]
fn registry_version_and_policy() {
    let registry = error_code_registry();
    assert_eq!(registry.version, ERROR_CODE_REGISTRY_VERSION);
    assert_eq!(
        registry.compatibility_policy,
        ERROR_CODE_COMPATIBILITY_POLICY
    );
}

#[test]
fn registry_contains_all_codes() {
    let registry = error_code_registry();
    assert_eq!(registry.entries.len(), ALL_ERROR_CODES.len());
}

#[test]
fn registry_no_duplicate_numerics() {
    let registry = error_code_registry();
    let mut seen = std::collections::BTreeSet::new();
    for entry in &registry.entries {
        assert!(
            seen.insert(entry.numeric),
            "duplicate numeric {} in registry",
            entry.numeric
        );
    }
}

#[test]
fn registry_no_duplicate_stable_codes() {
    let registry = error_code_registry();
    let mut seen = std::collections::BTreeSet::new();
    for entry in &registry.entries {
        assert!(
            seen.insert(entry.code.clone()),
            "duplicate stable code {} in registry",
            entry.code
        );
    }
}

#[test]
fn registry_serde_round_trip() {
    let registry = error_code_registry();
    let json = serde_json::to_string(&registry).unwrap();
    let back: ErrorCodeRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, registry);
}

// ===========================================================================
// 12. Specific error code spot-checks
// ===========================================================================

#[test]
fn capability_denied_error_details() {
    let code = FrankenErrorCode::CapabilityDeniedError;
    assert_eq!(code.numeric(), 2000);
    assert_eq!(code.stable_code(), "FE-2000");
    assert_eq!(code.subsystem(), ErrorSubsystem::CapabilityAuthorization);
    assert_eq!(code.severity(), ErrorSeverity::Error);
    assert!(code.description().contains("apability") || code.description().contains("denied"));
}

#[test]
fn serialization_encoding_codes() {
    assert_eq!(FrankenErrorCode::NonCanonicalEncodingError.numeric(), 1);
    assert_eq!(FrankenErrorCode::DeterministicSerdeError.numeric(), 2);
    assert_eq!(
        FrankenErrorCode::NonCanonicalEncodingError.subsystem(),
        ErrorSubsystem::SerializationEncoding
    );
}

#[test]
fn epoch_monotonicity_is_critical() {
    let code = FrankenErrorCode::EpochMonotonicityViolation;
    assert_eq!(code.numeric(), 8000);
    assert_eq!(code.severity(), ErrorSeverity::Critical);
    assert_eq!(code.subsystem(), ErrorSubsystem::LifecycleMigration);
}

// ===========================================================================
// 13. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_registry_lookup() {
    // Build registry
    let registry = error_code_registry();
    assert_eq!(registry.version, 1);

    // Look up a code by numeric
    let code = FrankenErrorCode::from_numeric(4000).unwrap();
    assert_eq!(code, FrankenErrorCode::RevocationChainIntegrityError);
    assert_eq!(code.severity(), ErrorSeverity::Critical);

    // Find it in the registry
    let entry = registry.entries.iter().find(|e| e.numeric == 4000).unwrap();
    assert_eq!(entry.code, "FE-4000");
    assert_eq!(entry.subsystem, ErrorSubsystem::Revocation);

    // Verify subsystem range
    let (lo, hi) = ErrorSubsystem::Revocation.range();
    assert!(lo <= 4000 && 4000 <= hi);

    // Serde round-trip of the entry
    let json = serde_json::to_string(entry).unwrap();
    let back: ErrorCodeEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, entry);
}

#[test]
fn error_code_registry_debug_is_nonempty() {
    let registry = error_code_registry();
    assert!(!format!("{registry:?}").is_empty());
}

#[test]
fn error_code_entry_debug_is_nonempty() {
    let registry = error_code_registry();
    let entry = registry
        .entries
        .first()
        .expect("registry must have entries");
    assert!(!format!("{entry:?}").is_empty());
}

#[test]
fn error_code_registry_serde_is_deterministic() {
    let registry = error_code_registry();
    let a = serde_json::to_string(&registry).expect("first");
    let b = serde_json::to_string(&registry).expect("second");
    assert_eq!(a, b);
}

// ===========================================================================
// 14. FrankenErrorCode — Hash trait determinism
// ===========================================================================

#[test]
fn error_code_hash_determinism() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    for &code in ALL_ERROR_CODES {
        let mut h1 = DefaultHasher::new();
        code.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        code.hash(&mut h2);
        let hash2 = h2.finish();

        assert_eq!(hash1, hash2, "hash not deterministic for {code:?}");
    }
}

#[test]
fn distinct_error_codes_produce_distinct_hashes() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hashes = std::collections::BTreeSet::new();
    for &code in ALL_ERROR_CODES {
        let mut h = DefaultHasher::new();
        code.hash(&mut h);
        hashes.insert(h.finish());
    }
    // All 42 codes should produce distinct hashes
    assert_eq!(hashes.len(), ALL_ERROR_CODES.len());
}

// ===========================================================================
// 15. FrankenErrorCode — Clone/Copy semantics
// ===========================================================================

#[test]
fn error_code_clone_equals_original() {
    for &code in ALL_ERROR_CODES {
        let cloned = code.clone();
        assert_eq!(cloned, code);
        assert_eq!(cloned.numeric(), code.numeric());
        assert_eq!(cloned.stable_code(), code.stable_code());
    }
}

#[test]
fn error_code_copy_semantics() {
    let code = FrankenErrorCode::ForkDetectionError;
    let copied = code;
    // Both remain usable (Copy trait)
    assert_eq!(code.numeric(), copied.numeric());
    assert_eq!(code.stable_code(), copied.stable_code());
    assert_eq!(code.severity(), copied.severity());
}

// ===========================================================================
// 16. ErrorSeverity — Clone, Debug, boundary
// ===========================================================================

#[test]
fn error_severity_clone_and_debug() {
    let severities = [
        ErrorSeverity::Critical,
        ErrorSeverity::Error,
        ErrorSeverity::Warning,
        ErrorSeverity::Info,
    ];
    for sev in &severities {
        let cloned = sev.clone();
        assert_eq!(&cloned, sev);
        let debug = format!("{sev:?}");
        assert!(!debug.is_empty());
    }
}

#[test]
fn error_severity_json_snake_case() {
    let json = serde_json::to_string(&ErrorSeverity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");

    let json = serde_json::to_string(&ErrorSeverity::Error).unwrap();
    assert_eq!(json, "\"error\"");

    let json = serde_json::to_string(&ErrorSeverity::Warning).unwrap();
    assert_eq!(json, "\"warning\"");

    let json = serde_json::to_string(&ErrorSeverity::Info).unwrap();
    assert_eq!(json, "\"info\"");
}

// ===========================================================================
// 17. ErrorSubsystem — boundary and coverage
// ===========================================================================

#[test]
fn every_subsystem_has_at_least_one_code() {
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
    ];
    for subsys in &subsystems {
        let count = ALL_ERROR_CODES
            .iter()
            .filter(|c| c.subsystem() == *subsys)
            .count();
        assert!(
            count >= 1,
            "subsystem {subsys:?} has no error codes assigned"
        );
    }
}

#[test]
fn subsystem_includes_boundary_values() {
    // Test that range boundaries work correctly for all subsystems
    let subsystems = [
        (ErrorSubsystem::SerializationEncoding, 1, 999),
        (ErrorSubsystem::IdentityAuthentication, 1000, 1999),
        (ErrorSubsystem::CapabilityAuthorization, 2000, 2999),
        (ErrorSubsystem::CheckpointPolicy, 3000, 3999),
        (ErrorSubsystem::Revocation, 4000, 4999),
        (ErrorSubsystem::SessionChannel, 5000, 5999),
        (ErrorSubsystem::ZoneScope, 6000, 6999),
        (ErrorSubsystem::AuditObservability, 7000, 7999),
        (ErrorSubsystem::LifecycleMigration, 8000, 8999),
        (ErrorSubsystem::Reserved, 9000, 9999),
    ];
    for (subsys, lo, hi) in &subsystems {
        assert!(subsys.includes(*lo), "{subsys:?} should include {lo}");
        assert!(subsys.includes(*hi), "{subsys:?} should include {hi}");
        if *lo > 0 {
            assert!(
                !subsys.includes(lo - 1),
                "{subsys:?} should not include {}",
                lo - 1
            );
        }
        assert!(
            !subsys.includes(hi + 1),
            "{subsys:?} should not include {}",
            hi + 1
        );
    }
}

#[test]
fn subsystem_json_snake_case() {
    let json = serde_json::to_string(&ErrorSubsystem::SerializationEncoding).unwrap();
    assert_eq!(json, "\"serialization_encoding\"");

    let json = serde_json::to_string(&ErrorSubsystem::IdentityAuthentication).unwrap();
    assert_eq!(json, "\"identity_authentication\"");

    let json = serde_json::to_string(&ErrorSubsystem::Reserved).unwrap();
    assert_eq!(json, "\"reserved\"");
}

// ===========================================================================
// 18. Stable code zero-padding
// ===========================================================================

#[test]
fn stable_code_zero_padding_for_low_numerics() {
    let code = FrankenErrorCode::NonCanonicalEncodingError;
    assert_eq!(code.numeric(), 1);
    assert_eq!(code.stable_code(), "FE-0001");

    let code2 = FrankenErrorCode::DeterministicSerdeError;
    assert_eq!(code2.numeric(), 2);
    assert_eq!(code2.stable_code(), "FE-0002");
}

#[test]
fn stable_code_no_extra_padding_for_four_digit_numerics() {
    let code = FrankenErrorCode::CapabilityDeniedError;
    assert_eq!(code.numeric(), 2000);
    assert_eq!(code.stable_code(), "FE-2000");

    let code2 = FrankenErrorCode::EpochMonotonicityViolation;
    assert_eq!(code2.numeric(), 8000);
    assert_eq!(code2.stable_code(), "FE-8000");
}

// ===========================================================================
// 19. Description and operator_action uniqueness
// ===========================================================================

#[test]
fn all_descriptions_are_unique() {
    let mut descriptions = std::collections::BTreeSet::new();
    for &code in ALL_ERROR_CODES {
        assert!(
            descriptions.insert(code.description()),
            "duplicate description for {code:?}: {}",
            code.description()
        );
    }
}

#[test]
fn all_operator_actions_are_unique() {
    let mut actions = std::collections::BTreeSet::new();
    for &code in ALL_ERROR_CODES {
        assert!(
            actions.insert(code.operator_action()),
            "duplicate operator_action for {code:?}: {}",
            code.operator_action()
        );
    }
}

// ===========================================================================
// 20. ErrorCodeEntry — Clone
// ===========================================================================

#[test]
fn error_code_entry_clone_equality() {
    let entry = FrankenErrorCode::SagaExecutionError.to_registry_entry();
    let cloned = entry.clone();
    assert_eq!(cloned, entry);
    assert_eq!(cloned.code, entry.code);
    assert_eq!(cloned.numeric, entry.numeric);
    assert_eq!(cloned.subsystem, entry.subsystem);
    assert_eq!(cloned.severity, entry.severity);
    assert_eq!(cloned.description, entry.description);
    assert_eq!(cloned.operator_action, entry.operator_action);
    assert_eq!(cloned.deprecated, entry.deprecated);
}

// ===========================================================================
// 21. ErrorCodeRegistry — Clone
// ===========================================================================

#[test]
fn error_code_registry_clone_equality() {
    let registry = error_code_registry();
    let cloned = registry.clone();
    assert_eq!(cloned, registry);
    assert_eq!(cloned.version, registry.version);
    assert_eq!(cloned.compatibility_policy, registry.compatibility_policy);
    assert_eq!(cloned.entries.len(), registry.entries.len());
}

// ===========================================================================
// 22. From_numeric edge cases
// ===========================================================================

#[test]
fn from_numeric_returns_none_for_zero() {
    assert!(FrankenErrorCode::from_numeric(0).is_none());
}

#[test]
fn from_numeric_returns_none_for_gap_values() {
    // Values between assigned codes that should not resolve
    assert!(FrankenErrorCode::from_numeric(3).is_none()); // gap after 2
    assert!(FrankenErrorCode::from_numeric(500).is_none()); // gap in serialization range
    assert!(FrankenErrorCode::from_numeric(1500).is_none()); // gap in identity range
    assert!(FrankenErrorCode::from_numeric(4500).is_none()); // gap in revocation range
    assert!(FrankenErrorCode::from_numeric(9000).is_none()); // Reserved range, no codes assigned
}

// ===========================================================================
// 23. Severity distribution
// ===========================================================================

#[test]
fn severity_distribution_critical_vs_error() {
    let critical_count = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.severity() == ErrorSeverity::Critical)
        .count();
    let error_count = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.severity() == ErrorSeverity::Error)
        .count();
    // There should be exactly 5 critical codes
    assert_eq!(critical_count, 5);
    // The rest should be Error severity
    assert_eq!(error_count, ALL_ERROR_CODES.len() - critical_count);
    // No Warning or Info codes in v1
    let warning_count = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.severity() == ErrorSeverity::Warning)
        .count();
    let info_count = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.severity() == ErrorSeverity::Info)
        .count();
    assert_eq!(warning_count, 0);
    assert_eq!(info_count, 0);
}

// ===========================================================================
// 24. Registry JSON structure
// ===========================================================================

#[test]
fn registry_json_contains_expected_top_level_keys() {
    let registry = error_code_registry();
    let json_val: serde_json::Value = serde_json::to_value(&registry).unwrap();
    let obj = json_val.as_object().unwrap();
    assert!(obj.contains_key("version"));
    assert!(obj.contains_key("compatibility_policy"));
    assert!(obj.contains_key("entries"));
    assert_eq!(
        obj.len(),
        3,
        "registry should have exactly 3 top-level keys"
    );
}

#[test]
fn registry_entry_json_contains_expected_keys() {
    let entry = FrankenErrorCode::EvalRuntimeError.to_registry_entry();
    let json_val: serde_json::Value = serde_json::to_value(&entry).unwrap();
    let obj = json_val.as_object().unwrap();
    assert!(obj.contains_key("code"));
    assert!(obj.contains_key("numeric"));
    assert!(obj.contains_key("subsystem"));
    assert!(obj.contains_key("severity"));
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("operator_action"));
    assert!(obj.contains_key("deprecated"));
    assert_eq!(obj.len(), 7, "entry should have exactly 7 keys");
}

// ===========================================================================
// 25. Spot-checks for remaining subsystems
// ===========================================================================

#[test]
fn identity_authentication_subsystem_codes() {
    let codes = [
        FrankenErrorCode::EngineObjectIdError,
        FrankenErrorCode::SignatureVerificationError,
        FrankenErrorCode::MultiSigVerificationError,
        FrankenErrorCode::KeyDerivationFailure,
    ];
    for code in &codes {
        assert_eq!(
            code.subsystem(),
            ErrorSubsystem::IdentityAuthentication,
            "{code:?} should be in IdentityAuthentication subsystem"
        );
        assert_eq!(code.severity(), ErrorSeverity::Error);
    }
    assert_eq!(codes[0].numeric(), 1000);
    assert_eq!(codes[1].numeric(), 1001);
    assert_eq!(codes[2].numeric(), 1002);
    assert_eq!(codes[3].numeric(), 1003);
}

#[test]
fn session_channel_subsystem_codes() {
    let codes = [
        FrankenErrorCode::LeaseLifecycleError,
        FrankenErrorCode::ObligationChannelError,
        FrankenErrorCode::IdempotencyWorkflowError,
        FrankenErrorCode::SchedulerLaneAdmissionError,
        FrankenErrorCode::SagaExecutionError,
        FrankenErrorCode::BulkheadIsolationError,
        FrankenErrorCode::MonitorSchedulerError,
    ];
    for code in &codes {
        assert_eq!(
            code.subsystem(),
            ErrorSubsystem::SessionChannel,
            "{code:?} should be in SessionChannel subsystem"
        );
    }
    // Numerics should be 5000..=5006
    for (i, code) in codes.iter().enumerate() {
        assert_eq!(code.numeric(), 5000 + i as u16);
    }
}

#[test]
fn zone_scope_subsystem_codes() {
    let codes = [
        FrankenErrorCode::AllocationDomainBudgetError,
        FrankenErrorCode::RegionPhaseOrderError,
        FrankenErrorCode::SlotRegistryAuthorityError,
        FrankenErrorCode::GarbageCollectionError,
    ];
    for code in &codes {
        assert_eq!(
            code.subsystem(),
            ErrorSubsystem::ZoneScope,
            "{code:?} should be in ZoneScope subsystem"
        );
    }
    assert_eq!(codes[0].numeric(), 6000);
    assert_eq!(codes[1].numeric(), 6001);
    assert_eq!(codes[2].numeric(), 6002);
    assert_eq!(codes[3].numeric(), 6003);
}

#[test]
fn audit_observability_subsystem_has_most_codes() {
    let audit_count = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.subsystem() == ErrorSubsystem::AuditObservability)
        .count();
    // AuditObservability has 10 codes (7000..=7009), the most of any subsystem
    assert_eq!(audit_count, 10);

    // Verify the range
    let audit_codes: Vec<u16> = ALL_ERROR_CODES
        .iter()
        .filter(|c| c.subsystem() == ErrorSubsystem::AuditObservability)
        .map(|c| c.numeric())
        .collect();
    assert_eq!(*audit_codes.first().unwrap(), 7000);
    assert_eq!(*audit_codes.last().unwrap(), 7009);
}
