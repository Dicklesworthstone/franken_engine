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
